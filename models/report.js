const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const reportSchema = new Schema({
  patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient", required: true },
  title: { type: String, required: true, trim: true },
  reportDate: { type: Date, default: Date.now },
  reportFileUrl: { type: String, required: true }, // URL to the report file
}, { timestamps: true });
module.exports = mongoose.model("Report", reportSchema);