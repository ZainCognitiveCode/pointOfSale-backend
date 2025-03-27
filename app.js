const express = require('express');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');
const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const helmet = require('helmet');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');




const app = express();
app.use(express.json());


if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

app.use(cors({
    origin: "http://localhost:5173",
    methods: "GET,POST,PUT,PATCH,DELETE",
    credentials: true
}));
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(helmet());





const userRouter = require('./routes/userRoutes');
const productRouter = require('./routes/productRoutes');
const salesRouter = require('./routes/salesRoutes');

if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}



app.use('/users', userRouter);
app.use('/products', productRouter);
app.use('/sales', salesRouter);



app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
})


app.use(globalErrorHandler)
module.exports = app;
