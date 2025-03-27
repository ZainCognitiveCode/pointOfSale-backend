const User = require('./../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Email = require('../utils/email');
const { promisify } = require('util');


// Making jwt token
const signToken = id => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
}

// After Creating the token,sending it to user via cookie or response
const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        httpOnly: true
    }

    if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
    res.cookie('jwt', token, cookieOptions)
    user.password = undefined; // yani data mein password undefined show ho
    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user
        }
    })

}


exports.signup = catchAsync(async (req, res, next) => {
    const { email } = req.body;
    if (!process.env.JWT_SECRET) {
        console.error("JWT_SECRET is not defined in environment variables.");
        return next(new AppError('Internal Server Error', 500));
    }

    const userExist = await User.findOne({ email }); // ✅ Correct syntax
    if (userExist) {
        return next(new AppError('User with this email already exists', 400));
    }



    const newUser = await User.create(req.body);
    createSendToken(newUser, 201, res);
})




exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return next(new AppError('Please provide email and password', 400));
    }

    // Agar mein +password na krta to mein password nhi get kr skta tha kyunky iska select false h
    const user = await User.findOne({ email }).select('+password');

    if (!user) return next(new AppError('User not found', 400));

    if (!await user.correctPassword(password, user.password)) {
        return next(new AppError('Incorrect email or password', 401));
    }

    createSendToken(user, 200, res);

})


exports.logout = (req, res) => {
    res.cookie('jwt', 'loggedOut', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    });

    res.status(200).json({ status: 'Success' })
}

exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }
    if (!token) return next(new AppError('You are not logged in! Please login to get Access', 401));

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);


    const currentUser = await User.findById(decoded.id);
    if (!currentUser) return next(new AppError('The user belonging to this token does not exist.', 401));

    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(new AppError('User recently changed password! Please login again', 401));

    }

    req.user = currentUser;
    next();
})

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new AppError('You donot have permission to perform this action.', 403));
        }

        next();
    }
}


exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });

    if (!user) return next(new AppError('There is no user with that email address', 404));

    // First we are getting simple token from here,we have encrypted the token in the createPasswordResetToken method and set it in the DB
    // but when we wiould have to reset the Password then we will encrypt it again to compare it with the DB reset encrypted password.
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    try {
        const resetURL = `${req.protocol}://${req.get('host')}/users/resetPassword/${resetToken}`

        await new Email(user, resetURL).sendPasswordReset();
        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        })

    } catch (error) {
        user.createPasswordResetToken = undefined;
        user.createPasswordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError('There was an error sending the email, Try again later!', 500));
    }
})


exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({ passwordResetToken: hashToken, passwordResetExpires: { $gt: Date.now() } })

    if (!user) return next(new AppError('Token is invalid or has expired.', 400))

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createSendToken(user, 200, res);
})

