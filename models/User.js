const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  displayName: String,
  profilePicture: String, // Add a field for profile picture file path or URL
  skills: String,
  occupation: String,
  country: String,
  city: String,
  phoneNumber: String,
  interests: String,
  gender: { type: String, enum: ['male', 'female', 'other'] },
  maritalStatus: { type: String, enum: ['single', 'married', 'divorced', 'widowed'] },
  googleId: String,
  facebookId: String,
});

userSchema.methods.validPassword = function (password) {
  return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', userSchema);
