const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const multer = require('multer');
const sharp = require('sharp');


const multerStorage = multer.memoryStorage();
const multerFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image')) {
        cb(null, true)
    } else {
        cb(new AppError('Not an image! Please upload only images.', 400), false)
    }
}


const upload = multer({
    storage: multerStorage,
    fileFilter: multerFilter
});

exports.uploadUserPhoto = upload.single('photo');

exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
    if (!req.file) return next();

    req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`;

    await sharp(req.file.buffer)
        .resize(500, 500)
        .toFormat('jpeg')
        .jpeg({ quality: 90 })
        .toFile(`public/img/users/${req.file.filename}`);

    next();
})




exports.createUser = (req, res) => {
    res.status(500).json({
        status: 'error',
        message: 'This route is not defined! Please use /signup instead'
    });
};


exports.getUser = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) return next(new AppError(`No User found with that ID`, 404));

    res.status(200).json({
        status: 'Success',
        data: {
            user
        }
    })


})


exports.getUsers = catchAsync(async (req, res, next) => {
    const users = await User.find();
    res.status(200).json({
        status: 'Success',
        results: users.length,
        data: users
    });
})


exports.updateUser = catchAsync(async (req, res, next) => {

    const { id } = req.params;
    console.log("File uploaded:", req.file);


    if (req.file) {
        req.body.image = `user-${Date.now()}.jpeg`;
        await sharp(req.file.buffer)
            .toFormat('jpeg')
            .jpeg({ quality: 90 })
            .toFile(`public/img/users/${req.body.image}`);
    }

    const user = await User.findByIdAndUpdate(id, req.body, { new: true, runValidators: true });


    if (!user) return next(new AppError('No user found with that ID', 404));


    res.status(200).json({
        status: 'Success',
        data: {
            user
        }
    })


})


exports.deleteUser = catchAsync(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) return next(new AppError(`No user found with that ID`, 404));

    res.status(204).json({
        status: 'Success',
        data: 'User deleted Successfully'
    });
})






