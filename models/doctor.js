const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const doctorSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^\+?[0-9]{10,15}$/, 'Please enter a valid phone number']
  },
  email: {
  type: String,
  required: true,
  unique: true,
  validate: {
    validator: function (v) {
      // Simple email regex
      return /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
    },
    message: 'Please enter a valid email address'
  }
},
  licenseId: {
    type: String,
    required: true,
    uppercase: true,
    trim: true,
    unique: true,
  },
  clinicLocation: {
    type: String,
    required: true,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  chatLink: {
    type: String,
    unique: true
  },
  patients: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'patient'
    }
  ],
  appointments: [
    {
      patient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Patient",
      },
      date: {
        type: String, // e.g., '2025-05-23'
        required: true,
      },
      time: {
        type: String, // e.g., '14:30'
        required: true,
      },
    },
  ],
  role: { type: String, default: 'doctor' },
  qr: {
    type: String,
    unique: true,
    sparse: true // Allows for null values without enforcing uniqueness
  }
});

doctorSchema.plugin(passportLocalMongoose, { usernameField: 'phoneNumber' });

module.exports = mongoose.model('Doctor', doctorSchema);
