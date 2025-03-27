const express = require('express');
const authController = require('./../controllers/authController');
const SalesController = require('./../controllers/SalesController');


const router = express.Router();

router.use(authController.protect, authController.restrictTo('admin'));

router.route('/')
    .get(SalesController.getSales);



module.exports = router;