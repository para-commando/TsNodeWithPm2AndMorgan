 const express = require('express');
const app = express();
const morgan = require('morgan');
app.use(morgan('combined'));

const add = (number1: number, number2: number): number => number1+number2 ;
app.get('/123', (req:Request, res:any)=>{

    // console.log(add(2,3));
        res.send('fwefefdsdwe232df')
    })
    


app.listen(3000, () => {
  console.log('App listening on port 3000');
});