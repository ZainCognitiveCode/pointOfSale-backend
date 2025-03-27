const mongoose = require('mongoose');

function mongoDb() {
    const DB = process.env.MONGO_URI;
    mongoose.connect(DB).then(con => {
        console.log('MongoDB Connected Successfully!');
    }).catch(err => console.log('Error Connecting MongoDB: ', err.message));
}

module.exports = mongoDb;