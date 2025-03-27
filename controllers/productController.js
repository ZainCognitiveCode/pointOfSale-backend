const Product = require('./../models/productModel');
const Sales = require('./../models/salesModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const multer = require('multer');
const sharp = require('sharp');
const { default: mongoose } = require('mongoose');

const multerStorage = multer.memoryStorage();


const multerFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image')) {
        console.log(file)
        cb(null, true)
    } else {
        cb(new AppError('Not an image! Please upload only images.', 400), false)
    }
}
const upload = multer({
    storage: multerStorage,
    fileFilter: multerFilter
});


exports.uploadImage = upload.single('image');

exports.resizeProductPhoto = catchAsync(async (req, res, next) => {
    console.log('File received:', req.file);
    if (!req.file) return next();

    req.body.image = `product-${Date.now()}.jpeg`;

    await sharp(req.file.buffer)
        .toFormat('jpeg')
        .jpeg({ quality: 90 })
        .toFile(`public/img/products/${req.body.image}`);



    next();
})



exports.createProduct = catchAsync(async (req, res, next) => {
    const product = await Product.create(req.body);


    res.status(200).json({
        status: 'Success',
        data: {
            data: product
        }
    })
})



exports.getOne = catchAsync(async (req, res, next) => {
    const { id } = req.params;

    const product = await Product.findById(id);

    if (!product) return next(new AppError(`No product found with that ID`, 404));

    res.status(200).json({
        status: 'Success',
        data: {
            product
        }
    })


})






exports.getProducts = catchAsync(async (req, res, next) => {
    const products = await Product.find();
    res.status(200).json({
        status: 'Success',
        results: products.length,
        data: products
    });
})



exports.updateProduct = catchAsync(async (req, res, next) => {
    const { id } = req.params;

    if (req.file) {
        req.body.image = `product-${Date.now()}.jpeg`;
        await sharp(req.file.buffer)
            .toFormat('jpeg')
            .jpeg({ quality: 90 })
            .toFile(`public/img/products/${req.body.image}`);
    }

    const product = await Product.findByIdAndUpdate(id, req.body, { new: true, runValidators: true });

    if (!product) return next(new AppError('No product found with that ID', 404));


    res.status(200).json({
        status: 'Success',
        data: {
            product
        }
    })
})




exports.deleteProduct = catchAsync(async (req, res, next) => {
    const product = await Product.findByIdAndDelete(req.params.id);

    if (!product) return next(new AppError(`No product found with that ID`, 404));

    res.status(204).json({
        status: 'Success'
    });
})



exports.BulkUpdate = async (req, res) => {
    const soldProducts = req.body;

    try {
        const bulkOperations = soldProducts.map((product) => ({
            updateOne: {
                filter: { _id: new mongoose.Types.ObjectId(product.itemId) },
                update: { $inc: { stockQuantity: -product.quantity } },
            },
        }))
        for (let i = 0; i < soldProducts.length; i++) {
            let productSold = await Product.findOne({ _id: soldProducts[i].itemId })
            let newSales = await Sales.create({
                name: soldProducts[i].name,
                price: productSold.price - ((productSold.price / 100) * 5),
            })
        }
        await Product.bulkWrite(bulkOperations);

        const updatedProducts = await Product.find({
            _id: { $in: soldProducts.map(p => p.itemId) }
        });

        res.status(200).json({
            status: "Success",
            message: "Stock Updated Successfully",
            updatedProducts
        })
    } catch (error) {
        console.error("Error updating stock:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}


