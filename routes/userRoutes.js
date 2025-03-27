const express = require('express');

const userController = require('./../controllers/userController')
const authController = require('./../controllers/authController');

const router = express.Router();

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);



router.use(authController.protect, authController.restrictTo('admin'));

router.route('/')
    .get(userController.getUsers)
    .post(userController.createUser);

router.route('/:id')
    .get(userController.getUser)
    .patch(userController.uploadUserPhoto, userController.resizeUserPhoto, userController.updateUser)
    .delete(userController.deleteUser);

module.exports = router;