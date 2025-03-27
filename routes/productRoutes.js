const express = require('express');
const productController = require('./../controllers/productController');
const authController = require('./../controllers/authController');
const router = express.Router();



router.use(authController.protect);
router.route('/').get(productController.getProducts).patch(productController.BulkUpdate);

router.use(authController.restrictTo('admin'));
router.route('/').post(productController.uploadImage, productController.resizeProductPhoto, productController.createProduct);

router.route('/:id').get(productController.getOne)
    .patch(productController.uploadImage, productController.resizeProductPhoto, productController.updateProduct)
    .delete(productController.deleteProduct)


module.exports = router;