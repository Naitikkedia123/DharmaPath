const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');
const medicationSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
    dosage: {
        type: String,
        required: true,
        trim: true
    },
    patient: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'Patient'
    },
    doctor: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'Doctor'
    },
    frequency: {
        type: String,
        required: true,
        trim: true
    },
    duration: {
        type: String,
        required: true,
        trim: true
    },
}, { timestamps: true });

module.exports = mongoose.model('Medication', medicationSchema);