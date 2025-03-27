const Sales = require('./../models/salesModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');


exports.getSales = catchAsync(async (req, res, next) => {
    const newSales = await Sales.find();
    res.status(200).json({
        status: 'Success',
        data: newSales,
    });
})
