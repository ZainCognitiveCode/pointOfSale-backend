const mongoDB = require('./DB/mongo');
const dotenv = require('dotenv');
const app = require('./app');


dotenv.config({ path: './config.env' });


process.on('uncaughtException', err => {
    console.log('Uncaught Exception! Shutting Down...');
    console.log(err.name, err.message);
    process.exit(1);
})


mongoDB();


const port = process.env.PORT;
const server = app.listen(port, () => {
    console.log(`App running on port ${port}...`)
})



process.on('unhandledRejection', err => {
    console.log('Unhandled rejection! Shutting Down...');
    console.log(err.name, err.message);
    server.close(() => {
        process.exit(1);

    });
})
