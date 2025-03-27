const mongoose = require('mongoose');

const salesSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please enter the product name']
    },

    price: {
        type: Number,
        required: [true, 'A product must have a price']
    },

}, {
    timestamps: true,
});
const Sales = mongoose.model("Sales", salesSchema);
module.exports = Sales;
