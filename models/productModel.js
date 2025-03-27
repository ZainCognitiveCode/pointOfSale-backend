const mongoose = require('mongoose');
const slugify = require('slugify');



const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please enter the product name']
    },
    slug: String,
    description: {
        type: String,
        required: [true, 'Please provide the product description']
    },
    price: {
        type: Number,
        required: [true, 'A product must have a price']
    },
    stockQuantity: {
        type: Number,
        required: [true, 'A product must have stockQuantity']
    },
    image: {
        type: String,
        required: [true, 'A product must have an Image']
    },
    category: {
        type: String,
        required: [true, 'A product must have a Category']
    }

});

productSchema.index({ slug: 1 });
productSchema.index({ price: 1 });


productSchema.pre('save', function (next) {
    this.slug = slugify(this.name, { lower: true });
    next();
})

const Product = mongoose.model('Product', productSchema);
module.exports = Product;