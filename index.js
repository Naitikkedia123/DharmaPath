const express = require('express');
const path = require('path');
const http = require('http');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const { Server } = require('socket.io');
const fs = require('fs');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const Doctor = require('./models/doctor');
const Patient = require('./models/patient');
const Chat = require('./models/chat');
const Timeline = require("./models/timeline");
const { isLoggedIn, isDoctor, isPatient } = require('./middleware');
const Report = require('./models/report'); // Assuming you have a Report model
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const medication = require('./models/medication'); // Assuming you have a Medication model
const qrDir = path.join(__dirname, 'public', 'qrcodes');
if (!fs.existsSync(qrDir)) {
  fs.mkdirSync(qrDir, { recursive: true });
}

const onlineUsers = new Map();
const multer = require('multer');
const { cloudinary, storage } = require('./utils/cloudinary');
const { constants } = require('buffer');
const doctor = require('./models/doctor');
const upload = multer({ storage });
const router = express.Router();


// MongoDB Connection
mongoose.connect('mongodb+srv://kedianaitik2006:dAPux89zFb7rWKkD@cluster0.l3nvspt.mongodb.net/')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Middleware
app.use(methodOverride('_method'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/uploads', express.static('uploads'));

// Session
const sessionStore = MongoStore.create({
  mongoUrl: 'mongodb+srv://kedianaitik2006:dAPux89zFb7rWKkD@cluster0.l3nvspt.mongodb.net/',
  crypto: { secret: 'your-secret-key' },
  touchAfter: 24 * 3600
});
app.use(session({
  store: sessionStore,
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,
    httpOnly: true
  }
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

passport.use('doctor', new LocalStrategy({ usernameField: 'phoneNumber' }, Doctor.authenticate()));
passport.use('patient', new LocalStrategy({ usernameField: 'phoneNumber' }, Patient.authenticate()));

passport.serializeUser((user, done) => {
  const type = user instanceof Doctor ? 'Doctor' : 'Patient';
  done(null, { id: user.id, type });
});

passport.deserializeUser(async (obj, done) => {
  try {
    const model = obj.type === 'Doctor' ? Doctor : Patient;
    const user = await model.findById(obj.id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Global user
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

// Routes
app.get('/', (req, res) => {
  res.send('Welcome to Dharma!');
});

app.post('/upload-image', upload.single('image'), async (req, res) => {
  try {
    const { to, caption } = req.body;
    const from = req.user._id;

    const fromModel = req.user.role.charAt(0).toUpperCase() + req.user.role.slice(1).toLowerCase();
    const toModel = fromModel === 'Doctor' ? 'Patient' : 'Doctor';

    const result = await cloudinary.uploader.upload(req.file.path);

    const chat = new Chat({
      from,
      fromModel,
      to,
      toModel,
      msg: result.secure_url,
      type: 'image',
      caption: caption || '',
      status: 'sent',
    });

    await chat.save();

    const doctorId = req.user.role === 'doctor' ? from : to;
    const patientId = req.user.role === 'patient' ? from : to;

    await Timeline.create({
      from,
      to,
      fromModel,
      toModel,
      doctorId,
      patientId,
      imageUrl: result.secure_url,
      caption: caption && caption.trim() !== '' ? caption.trim() : 'Treatment Update'
    });


    // ✅ Emit message
    const toSocketId = onlineUsers.get(to)?.socketId;
    const payload = {
      _id: chat._id,
      from,
      to,
      fromModel: req.user.role.toLowerCase(),
      toModel: toModel.toLowerCase(),
      msg: chat.msg,
      caption: chat.caption,
      type: 'image',
      createdAt: chat.createdAt,
      status: 'sent'
    };

    if (toSocketId) {
      payload.status = 'delivered';
      await chat.updateOne({ status: 'delivered' });
      io.to(toSocketId).emit('private message', payload);
    }

    io.to(onlineUsers.get(from.toString())?.socketId).emit('private message', payload);

    res.json({ success: true });
  } catch (err) {
    console.error('Image upload failed:', err);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

app.get('/doctor', (req, res) => {
  res.render('doctorregister', { currentUser: req.user });
});

app.get('/patient', (req, res) => {
  res.render('patientregister', { currentUser: req.user });
});

app.post('/prescribe-medication', async (req, res) => {
  const { patientId } = req.body;
  const medications = Object.values(req.body.medications); // array of meds
  const doctorId = req.user._id; // assuming user is authenticated doctor

  try {
    for (let med of medications) {
      await medication.create({
        ...med,
        patient: patientId,
        doctor: doctorId
      });
    }

    res.redirect(`/docpatient/${patientId}`); // redirect to patient profile
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving prescriptions.');
  }
});


app.post('/docregister', async (req, res) => {
  const { fullName, phoneNumber, email, licenseId, clinicLocation, password } = req.body;

  try {
    // Duplicate checks
    const existingPhone = await Doctor.findOne({ phoneNumber });
    if (existingPhone) return res.redirect('/doctor?error=duplicate_phone');

    const existingEmail = await Doctor.findOne({ email });
    if (existingEmail) return res.redirect('/doctor?error=duplicate_email');

    const existingLicense = await Doctor.findOne({ licenseId });
    if (existingLicense) return res.redirect('/doctor?error=duplicate_license');

    // Create doctor (but don't save yet)
    const newDoctor = new Doctor({
      fullName,
      phoneNumber,
      email,
      licenseId,
      clinicLocation,
      chatLink: uuidv4()
    });

    await Doctor.register(newDoctor, password);

    // Login doctor
    req.login(newDoctor, async (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/doctor?error=login_failed');
      }

      // Generate QR code image and save it temporarily
      const url = `https://dharmapath.onrender.com/connect/${newDoctor.chatLink}`;
      const qrFilePath = path.join(__dirname, 'temp', `${newDoctor._id}-qr.png`);

      // Ensure temp folder exists
      const tempDir = path.dirname(qrFilePath);
      if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

      await QRCode.toFile(qrFilePath, url);

      // Upload QR to Cloudinary
      const qrUpload = await cloudinary.uploader.upload(qrFilePath, {
        folder: 'doctor_qrcodes'
      });

      // Store QR URL in DB
      newDoctor.qr = qrUpload.secure_url;
      await newDoctor.save();

      // Clean up temp file
      fs.unlinkSync(qrFilePath);

      return res.redirect('/doctor-dashboard?status=success');
    });

  } catch (err) {
    // Mongoose validation error
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors)
        .map(e => e.message)
        .join(', ');
      return res.redirect(`/doctor?error=validation&details=${encodeURIComponent(messages)}`);
    }

    console.error(err);
    return res.redirect('/doctor?error=unknown');
  }
});


app.post('/patientregister', async (req, res) => {
  const { fullName, phoneNumber, email, password, age, gender } = req.body;

  try {
    const existingPhone = await Patient.findOne({ phoneNumber });
    if (existingPhone) return res.redirect('/patient?error=duplicate_phone');

    const existingEmail = await Patient.findOne({ email });
    if (existingEmail) return res.redirect('/patient?error=duplicate_email');

    const newPatient = new Patient({ fullName, phoneNumber, email, age, gender,chatLink: uuidv4()});

    await Patient.register(newPatient, password);

    req.login(newPatient, (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/patient?error=login_failed');
      }
      return res.redirect('/patient-dashboard?status=success');
    });
  } catch (err) {
    console.error(err);

    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map(e => e.message).join(', ');
      return res.redirect(`/patient?error=validation&details=${encodeURIComponent(messages)}`);
    }

    return res.redirect('/patient?error=internal');
  }
});

// Doctor login
app.get('/doctorlogin', (req, res) => {
  res.render('doctorlogin', { error: null });
});

app.post('/doctorlogin', (req, res, next) => {
  passport.authenticate('doctor', (err, user, info) => {
    if (err || !user) {
      return res.render('doctorlogin', { error: 'Invalid credentials' });
    }
    req.logIn(user, err => {
      if (err) return res.render('doctorlogin', { error: 'Login failed' });
      return res.redirect('/doctor-dashboard');
    });
  })(req, res, next);
});

// Patient login
app.get('/patientlogin', (req, res) => {
  res.render('patientlogin', { error: null });
});

app.post('/patientlogin', (req, res, next) => {
  passport.authenticate('patient', (err, user, info) => {
    if (err || !user) {
      return res.render('patientlogin', { error: 'Invalid credentials' });
    }
    req.logIn(user, err => {
      if (err) return res.render('patientlogin', { error: 'Login failed' });
      return res.redirect('/patient-dashboard');
    });
  })(req, res, next);
});

app.get('/doctor-dashboard', isDoctor, async (req, res) => {
  const qrPath = `/qrcodes/${req.user._id}.png`;

  const patients = await Patient.find({
    _id: { $in: req.user.patients }
  });

  const doctor = await Doctor.findById(req.user._id)
    .populate('appointments.patient', 'fullName gender')
    .lean();

  const now = new Date();

  // Filter upcoming appointments
  const appointments = (doctor.appointments || []).filter(appt => {
    const apptDateTime = new Date(`${appt.date}T${appt.time}`);
    return apptDateTime > now;
  });

  res.render('doctor-dashboard', {
    currentUser: req.user,
    qrPath,
    patients,
    appointments
  });
});


app.get('/patient-dashboard', isPatient, async (req, res) => {
  const error = req.query.error;
  const doctorid = req.user.doctors[0] ? req.user.doctors[0] : null;

  let doctor = null;
  let appointments = [];
  if (doctorid) {
    doctor = await Doctor.findById(doctorid).lean();

    // Find upcoming appointments for this patient
    const now = new Date();

    appointments = (doctor.appointments || []).filter(appt => {
      return (
        String(appt.patient) === String(req.user._id) &&
        new Date(`${appt.date}T${appt.time}`) > now
      );
    });
  }
 const timeline = await Timeline.find({ patientId: req.user._id })
  .populate('from', 'fullName role')   // Populate `from` with only fullName
  .populate('to', 'fullName role')     // Populate `to` with only fullName
  .sort({ createdAt: 1 });
  const medications = await medication.find({ patient: req.user._id, doctor: doctorid }).populate('doctor', 'fullName');
  res.render('patient-dashboard', {
    currentUser: req.user,
    error,
    doctor,
    appointments,
    timeline,
    medications
  });
});

app.get('/docpatient/:id', isDoctor, async (req, res) => {
  const { id } = req.params;

  try {
    const now = new Date(); // <-- this was missing

    const patient = await Patient.findById(id).populate('appointments.doctor', 'fullName gender');
    if (!patient) return res.redirect('/doctor-dashboard?error=Patient not found');

    const appointments = (req.user.appointments || []).filter(appt => {
      return (
        String(appt.patient) === String(patient._id) &&
        new Date(`${appt.date}T${appt.time}`) > now
      );
    });
   const timeline = await Timeline.find({ patientId: id })
  .populate('from', 'fullName role')   // Populate `from` with only fullName
  .populate('to', 'fullName role')     // Populate `to` with only fullName
  .sort({ createdAt: 1 });
    const medications = await medication.find({ patient: patient._id, doctor:req.user._id}).populate('doctor', 'fullName');
    res.render('docpatient', {
      currentUser: req.user,
      patient,
      appointments,
      timeline,
      medications
    });
  } catch (err) {
    console.error(err);
    res.redirect('/doctor-dashboard?error=Something went wrong');
  }
});


app.get('/end-treatment', isPatient, async (req, res) => {
  const patient = req.user;

  try {
    if (patient.doctors.length === 0) {
      return res.redirect('/patient-dashboard?error=You are not connected to any doctor');
    }

    const doctorId = patient.doctors[0];
    const doctor = await Doctor.findById(doctorId);

    if (doctor) {
      // Remove patient from doctor's list
      doctor.patients = doctor.patients.filter(p => p.toString() !== patient._id.toString());
      await doctor.save();
    }

    // Clear doctor from patient
    patient.doctors = [];
    await patient.save();

    await Timeline.deleteMany({
      $or: [
        { from: patient._id, fromModel: 'Patient' },
        { to: patient._id, toModel: 'Patient' }
      ]
    });
    await Chat.deleteMany({ $or: [{ from: patient._id }, { to: patient._id }] });
    await medication.deleteMany({ patient: patient._id, doctor: doctorId });
    return res.redirect('/patient-dashboard?success=Treatment ended successfully');
  } catch (err) {
    console.error(err);
    return res.redirect('/patient-dashboard?error=Something went wrong');
  }
});
app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/home?status=loggedout');
  });
});
app.post('/delete-medication/:id', async (req, res) => {
  try {
    const Medication = await medication.findById(req.params.id);
    await medication.findByIdAndDelete(req.params.id);
    res.redirect(`/docpatient/${Medication.patient}`);
  } catch (err) {
    console.error('Error deleting medication:', err);
    res.status(500).send('Failed to delete medication.');
  }
});
app.get('/home', (req, res) => {
  res.render('home', {
    currentUser: req.user,
    onlineUserIds: Array.from(onlineUsers.keys())
  });
});

app.get('/connect/:chatLink', isPatient, async (req, res) => {
  const { chatLink } = req.params;
  const patient = req.user;
  
  try {
    const doctor = await Doctor.findOne({ chatLink });
    if (!doctor) return res.redirect('/home?error=doctor_not_found');

    // Check if patient is already in treatment with a doctor
    if (patient.doctors.length > 0) {
      // Fetch the currently assigned doctor to display name
      const existingDoctor = await Doctor.findById(patient.doctors[0]);
      const doctorName = existingDoctor ? `Dr. ${existingDoctor.fullName}` : 'a doctor';

      return res.redirect(`/patient-dashboard?error=You are already in treatment of ${doctorName}`);
    }
    // Add doctor to patient
    patient.doctors.push(doctor._id);
    await patient.save();

    // Add patient to doctor
    if (!doctor.patients.includes(patient._id)) {
      doctor.patients.push(patient._id);
      await doctor.save();
    }
    const from = req.user._id;
    const to = doctor._id;
    const doctorId = req.user.role === 'doctor' ? from : to;
    const patientId = req.user.role === 'patient' ? from : to;
    const fromModel = req.user.role.charAt(0).toUpperCase() + req.user.role.slice(1).toLowerCase();
    const toModel = fromModel === 'Doctor' ? 'Patient' : 'Doctor';
    await Timeline.create({
      from,
      to,
      fromModel,
      toModel,
      doctorId,
      patientId,
      caption: 'Treatment Started',
    });
    return res.redirect(`/patient-dashboard?status=connected&doctorName=${encodeURIComponent(doctor.fullName)}`);
  } catch (err) {
    console.error(err);
    return res.redirect('/home?status=error');
  }
});

app.get('/connectpatient/:chatLink', isDoctor, async (req, res) => {
  const { chatLink } = req.params;
  const doctor = req.user;

  try {
    const patient = await Patient.findOne({ chatLink });
    if (!patient) return res.redirect('/home?error=Patient_not_found');

    return res.redirect(`/${doctor._id}/privatechat/${patient._id}?role=Doctor`);
  } catch (err) {
    console.error(err);
    return res.redirect('/home?status=error');
  }
});
app.get('/:id/privatechat/:otherId', isLoggedIn, async (req, res) => {
  const { id, otherId } = req.params;

  try {
    const chats = await Chat.find({
      $or: [{ from: id, to: otherId }, { from: otherId, to: id }]
    }).populate('from to');

    const user = await Patient.findById(otherId) || await Doctor.findById(otherId);

    let role;
    if (await Doctor.findById(id)) role = 'doctor';
    else if (await Patient.findById(id)) role = 'patient';

    res.render('privatechat', {
      user,
      chats,
      currentUser: req.user,
      onlineUserIds: Array.from(onlineUsers.keys()),
      role // 👈 pass the role here
    });
  } catch (err) {
    console.error(err);
    res.redirect('/home?status=error');
  }
});


// Socket.IO
io.on('connection', socket => {
  socket.on('register', ({ userId, role }) => {
  if (!userId || !role) return;

  if (onlineUsers.has(userId)) {
    const oldSocketId = onlineUsers.get(userId).socketId;
    if (oldSocketId !== socket.id) {
      io.sockets.sockets.get(oldSocketId)?.disconnect();
    }
  }

  // ✅ store socketId AND role
  onlineUsers.set(userId, {
    socketId: socket.id,
    role: role.toLowerCase() // store as 'doctor' or 'patient'
  });

  socket.broadcast.emit('user status', { userId, status: 'online' });

  for (let [id] of onlineUsers.entries()) {
    socket.emit('user status', { userId: id, status: 'online' });
  }
});

  function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

async function getUserRoleAndInfo(userId) {
  let user = await Doctor.findById(userId).lean();
  if (user) return { role: 'doctor', user };

  user = await Patient.findById(userId).lean();
  if (user) return { role: 'patient', user };

  return null; // user not found
}

socket.on('private message', async ({ from, to, msg }) => {
  try {
    // Get roles and info from DB
    const fromInfo = await getUserRoleAndInfo(from);
    const toInfo = await getUserRoleAndInfo(to);

    if (!fromInfo || !toInfo) {
      console.error('User not found in database');
      return;
    }

    const fromModelName = capitalizeFirstLetter(fromInfo.role);
    const toModelName = capitalizeFirstLetter(toInfo.role);

    // Save chat message with status 'sent'
    const chat = new Chat({
      from,
      to,
      fromModel: fromModelName,
      toModel: toModelName,
      msg,
      status: 'sent'
    });

    await chat.save();

    // Check if recipient is online to emit message immediately
    const toSocketId = onlineUsers.get(to)?.socketId;

    const payload = {
      _id: chat._id,
      from,
      to,
      fromModel: fromInfo.role,
      toModel: toInfo.role,
      msg,
      createdAt: chat.createdAt
    };

    if (toSocketId) {
      chat.status = 'delivered';
      await chat.save();
      io.to(toSocketId).emit('private message', { ...payload, status: 'delivered' });
      socket.emit('private message', { ...payload, status: 'delivered' });
    } else {
      socket.emit('private message', { ...payload, status: 'sent' });
    }
  } catch (err) {
    console.error('Error in private message handler:', err);
  }
});

  socket.on('read message', async ({ messageId }) => {
    const chat = await Chat.findByIdAndUpdate(messageId, { status: 'read' });
    if (chat) {
      const fromSocket = onlineUsers.get(chat.from.toString());
      if (fromSocket) {
        io.to(fromSocket).emit('message read', { messageId });
      }
    }
  });
socket.on("schedule_appointment", async ({ doctorID, patientID, date, time }) => {
  try {
    // Update Doctor
    await Doctor.findByIdAndUpdate(doctorID, {
      $push: {
        appointments: {
          patient: patientID,
          date,
          time,
        },
      },
    });

    // Update Patient
    await Patient.findByIdAndUpdate(patientID, {
      $push: {
        appointments: {
          doctor: doctorID,
          date,
          time,
        },
      },
    });

  } catch (err) {
    console.error('Error scheduling appointment:', err);
  }
});

  socket.on('disconnect', () => {
    for (let [userId, data] of onlineUsers.entries()) {
    if (data.socketId === socket.id) {
      onlineUsers.delete(userId);
      socket.broadcast.emit('user status', { userId, status: 'offline' });
      break;
    }
  }

});

});
app.delete('/appointments/:id', async (req, res) => {
  const appointmentId = req.params.id;

  try {
    // Remove appointment from all doctors who have it
    await Doctor.updateMany(
      {},
      { $pull: { appointments: { _id: appointmentId } } }
    );

    // Also remove from patients if you have a similar structure (optional)
    await Patient.updateMany(
      {},
      { $pull: { appointments: { _id: appointmentId } } }
    );

    res.status(200).json({ message: 'Appointment cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling appointment:', error);
    res.status(500).json({ message: 'Failed to cancel appointment' });
  }
});
app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) {
      console.error(err);
      return res.redirect('/home?error=logout_failed');
    }
    res.redirect('/home?status=loggedout');
  });
});

server.listen(10000, () => {
  console.log('Server running on port 10000');
});
