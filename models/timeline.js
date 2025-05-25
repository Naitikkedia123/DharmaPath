const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const timelineSchema = new mongoose.Schema({
  from: {
    type: Schema.Types.ObjectId,
    required: true,
    refPath: 'fromModel'
  },
  fromModel: {
    type: String,
    required: true,
    enum: ['Doctor', 'Patient']
  },
  to: {
    type: Schema.Types.ObjectId,
    required: true,
    refPath: 'toModel'
  },
  toModel: {
    type: String,
    required: true,
    enum: ['Doctor', 'Patient']
  },

  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: "Doctor" },
  patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient" },
  imageUrl: String,
  caption: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Timeline", timelineSchema);
