"use strict";
const express = require('express');
const app = express();
const morgan = require('morgan');
app.use(morgan('combined'));
const add = (number1, number2) => number1 + number2;
app.get('/123', (req, res) => {
    // console.log(add(2,3));
    res.send('fwefefdsdwe232df');
});
app.listen(3000, () => {
    console.log('App listening on port 3000');
});
//# sourceMappingURL=app.js.map