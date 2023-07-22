import express from 'express';
import cors from 'cors';
import mysql from 'mysql';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import multer from 'multer';
import fs from 'fs';
import bodyParser from 'body-parser';
import { createProxyMiddleware } from 'http-proxy-middleware';
const salt = 10;

const app = express();
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET,POST,PUT,DELETE"],
    credentials: true
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use('/api', createProxyMiddleware({
    target: 'https://vapi.vnappmob.com',
    changeOrigin: true,
    onProxyRes: function (proxyRes, req, res) {
        proxyRes.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000';
    }
}));

const storageAvatar = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/avatar')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
})
const uploadAvatar = multer({
    storage: storageAvatar
}).single('avatar');


const db = mysql.createConnection({
    host: 'localhost',
    database: 'phone',
    user: 'react-buy-iphone',
    password: 'admin@123'
});


//Login-register
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not Authenticated" })
    } else {
        jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
            if (err) {
                return res.json({ Error: "Token is invalid" });
            } else {
                req.name = decoded.name;
                req.role = decoded.role;
                req.username = decoded.username;
                next();
            }
        })
    }
}
app.get('/', verifyUser, (req, res) => {
    return res.json({
        success: true,
        name: req.name,
        role: req.role,
        username: req.username
    });
})
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: false });
});
app.post(`/check-currentpass/:username`, (req, res) => {
    const username = req.params.username;
    const sql = 'SELECT * FROM user where username=?';
    db.query(sql, username, (err, data) => {
        if (data.length > 0) {
            bcrypt.compare(req.body.currentpass.toString(), data[0].password, (error, response) => {
                if (err) {
                    return res.json({ result: false });
                }
                if (response) {
                    return res.json({ result: true });
                }
                return res.json({ result: false });
            })
        } else {
            return res.json({ result: false });
        }
    })
})
app.post('/login', (req, res) => {
    const sql = "SELECT * FROM user where username=? or phonenumber=?";
    const values = [
        req.body.username,
    ]
    db.query(sql, [...values, ...values], (err, data) => {
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err)
                    return res.status(401).json({
                        success: false,
                        message: "Invalid something... !!!"
                    })
                if (response) {
                    const name = data[0].name;
                    const role = data[0].role;
                    const username = req.body.username;
                    const token = jwt.sign({ name, role, username }, 'jwt-secret-key', { expiresIn: '1d' });
                    res.cookie('token', token);
                    return res.status(200).json({
                        success: true,
                    });
                }
                return res.status(401).json({
                    success: false,
                    message: "Invalid something... !!!"
                })
            })
        } else {
            return res.status(401).json({
                success: false,
                message: "Invalid something... !!!"
            })
        }
    })
})
app.post(`/change-password/:username`, (req, res) => {
    const username = req.params.username;
    const sql = 'UPDATE user SET password=? where username=?';
    bcrypt.hash(req.body.newpass, salt, (err, hash) => {
        if (err) {
            console.log(err);
        }
        db.query(sql, [hash, username], (err, data) => {
            if (data) {
                return res.json({ change_password: true });
            } else {
                return res.json({ change_password: false });
            }
        })
    })
})
app.post('/register', (req, res) => {
    const sql = 'INSERT INTO user(username,password,name,phonenumber,email,address) VALUES(?,?,?,?,?,?);';
    bcrypt.hash(req.body.password, salt, (err, hash) => {
        if (err) {
            console.log(err);
        }
        const values = [
            req.body.username,
            hash,
            req.body.name,
            req.body.phonenumber,
            req.body.email,
            req.body.address
        ];
        db.query(sql, [...values], (err, data) => {
            if (data) {
                return res.status(200).json({
                    success: true,
                    user: data
                })
            } else {
                return res.status(500).json({
                    success: false,
                    message: "An error occurred during registration"
                })
            }
        })
    })
})
app.get('/check-email/:email', (req, res) => {
    const sql = 'SELECT * FROM user WHERE email=?';
    const email = req.params.email;
    db.query(sql, email, (err, data) => {
        if (data) {
            return res.json(data);
        }
        return res.json(err);
    })
})
//User
app.get('/user-by-username/:username', (req, res) => {
    const username = req.params.username;
    const sql = 'SELECT * FROM user WHERE username=?';
    db.query(sql, username, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})

app.post('/update-user/:username', (req, res) => {
    const username = req.params.username;
    const sql = `UPDATE user SET name = ?, phonenumber = ?, email = ?, address = ? WHERE username = '${username}'`;
    const reqBody = [
        req.body.name,
        req.body.phonenumber,
        req.body.email,
        req.body.address,
    ];
    db.query(sql, [...reqBody], (err, data) => {
        if (data) {
            return res.json({ update_user: true });
        } else if (err) {
            return res.json(err);
        }
        else {
            return res.json({ update_user: false });
        }
    })
})
const getUserAvatar = (username, callback) => {
    const sql = `SELECT avatar FROM user WHERE username = ?`;
    db.query(sql, [username], (err, result) => {
        if (err) {
            callback(err, null);
        } else {
            callback(null, result[0].avatar);
        }
    });
};
app.post('/upload-avatar/:username', uploadAvatar, (req, res) => {
    const image = req.file.filename;
    if (image !== '') {
        const username = req.params.username;
        getUserAvatar(username, (err, avatar) => {
            if (err) {
                return res.json(err);
            }
            if (avatar) {
                const avatarPath = path.join('public/avatar', avatar);
                fs.unlink(avatarPath, (err) => {
                    if (err) {
                        console.error('Error deleting current image:', err);
                    }
                });
            }
            const sql = `UPDATE user set avatar=? WHERE username='` + username + `'`;
            db.query(sql, [image], (err, data) => {
                if (data) {
                    return res.json({ upload_avatar: true });
                } else if (err) {
                    return res.json(err);
                } else {
                    return res.json({ upload_avatar: false });
                }
            })
        })
    }
})



//Order & orderdetail
app.get(`/show-details/:orderid`, (req, res) => {
    const orderid = req.params.orderid;
    const sql = "SELECT total,`order`.orderid, date, status,product.id, product.image, product.name, orderdetail.price, product.cost, orderdetail.quantity,colorname, memoryname FROM `order`, product, orderdetail, color, memory WHERE `order`.`orderid`=orderdetail.orderid AND orderdetail.productid=product.id AND product.colorid=color.colorid AND product.memoryid=memory.memoryid AND `order`.`orderid`='" + orderid + "'";
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get('/orderdetail-quantity/:orderid', (req, res) => {
    const sql = 'SELECT COUNT(`productid`) as "ordercount" FROM `orderdetail`, `order` WHERE orderdetail.orderid=`order`.`orderid` AND status=? AND orderdetail.orderid=?';
    const orderid = req.params.orderid;
    db.query(sql, ['unfinished', orderid], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get(`/get-all-order/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username='" + username + "'";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get(`/get-order-unconfirm/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username='" + username + "' AND status = 'unfinished'";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get(`/get-order-confirm/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username = '" + username + "' AND status IN ('finished', 'delivery', 'at the store')";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get(`/get-order-delivery/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username = '" + username + "' AND status='delivery'";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get(`/get-order-received/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username = '" + username + "' AND status='finished'";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get(`/get-order-cancel/:username`, (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username = '" + username + "' AND status='canceled'";
        db.query(getOrderid, (error, values) => {
            if (values) {
                return res.json(values);
            }
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})
app.get('/check-order-exist/:username', async (req, res) => {
    try {
        const username = req.params.username;
        const getOrderid = "SELECT * FROM `order` WHERE username=? and status='unfinished'";
        await db.query(getOrderid, [username], (error, values) => {
            if (values)
                return res.json(values);
            return res.json(error);
        })
    } catch (err) {
        reject(err);
    }
})

app.get('/increase-quantity/:orderid/:productid', (req, res) => {
    const productid = req.params.productid;
    const orderid = req.params.orderid;
    const getOrderDetailQuery = "SELECT * FROM `orderdetail` WHERE orderid=? and productid=?";
    db.query(getOrderDetailQuery, [orderid, productid], (error, results) => {
        if (error) {
            return res.json(error);
        }
        if (results.length === 0) {
            return res.json({
                result: false,
                message: "Order detail not found"
            });
        }
        const quantity = results[0].quantity;
        const selectProductQuantity = `SELECT quantity FROM product WHERE id='${productid}'`;
        db.query(selectProductQuantity, (er, rs) => {
            if (er) {
                return res.json(er);
            }
            const productQuantity = rs[0].quantity;
            if (quantity > 2) {
                const newQuantity = quantity;
                if (newQuantity <= productQuantity) {
                    const updateQuantityQuery = "UPDATE orderdetail SET quantity=? WHERE orderid=? and productid=?";
                    db.query(updateQuantityQuery, [newQuantity, orderid, productid], (err, data) => {
                        if (err) {
                            return res.json({
                                result: false,
                                message: "Failed to update quantity"
                            });
                        }
                        return res.json({
                            result: true,
                            message: "Quantity has reached the limit"
                        });
                    });
                } else if (newQuantity > productQuantity) {
                    const updateQuantityQuery = "UPDATE orderdetail SET quantity=? WHERE orderid=? and productid=?";
                    db.query(updateQuantityQuery, [productQuantity, orderid, productid], (err, data) => {
                        if (err) {
                            return res.json({
                                result: false,
                                message: "Failed to update quantity"
                            });
                        }
                        return res.json({
                            result: true,
                            message: "Quantity has reached the limit"
                        });
                    });
                }

            } else {
                const newQuantity = quantity + 1;
                if (newQuantity <= productQuantity) {
                    const updateQuantityQuery = "UPDATE orderdetail SET quantity=? WHERE orderid=? and productid=?";
                    db.query(updateQuantityQuery, [newQuantity, orderid, productid], (err, data) => {
                        if (err) {
                            return res.json({
                                result: false,
                                message: "Failed to update quantity"
                            });
                        }
                        return res.json({
                            result: true,
                            message: "Quantity increased successfully"
                        });
                    });
                } else if (newQuantity > productQuantity) {
                    const updateQuantityQuery = "UPDATE orderdetail SET quantity=? WHERE orderid=? and productid=?";
                    db.query(updateQuantityQuery, [productQuantity, orderid, productid], (err, data) => {
                        if (err) {
                            return res.json({
                                result: false,
                                message: "Failed to update quantity"
                            });
                        }
                        return res.json({
                            result: true,
                            message: "Quantity has reached the limit"
                        });
                    });
                }
            }
        })
    });
});
app.get('/decrease-quantity/:orderid/:productid', (req, res) => {
    const productid = req.params.productid;
    const orderid = req.params.orderid;
    const getOrderDetailQuery = "SELECT * FROM `orderdetail` WHERE orderid=? and productid=?";
    db.query(getOrderDetailQuery, [orderid, productid], (error, results) => {
        if (error) {
            return res.json(error);
        }
        if (results.length === 0) {
            return res.json({
                result: false,
                message: "Order detail not found"
            });
        }
        const quantity = results[0].quantity;
        if (quantity <= 1) {
            return res.json({
                result: true,
                message: "Reduced quantity has reached the limit"
            });
        } else {
            const newQuantity = quantity - 1;
            const updateQuantityQuery = "UPDATE orderdetail SET quantity=? WHERE orderid=? and productid=?";
            db.query(updateQuantityQuery, [newQuantity, orderid, productid], (err, data) => {
                if (err) {
                    return res.json({
                        result: false,
                        message: "Failed to update quantity"
                    });
                }
                return res.json({
                    result: true,
                    message: "Quantity decrease successfully"
                });
            });
        }
    });
});

app.get('/check-product-exist/:orderid/:productid', (req, res) => {
    const productid = req.params.productid;
    const orderid = req.params.orderid;
    const getOrderid = "SELECT * FROM `orderdetail` WHERE orderid=? and productid=?";
    db.query(getOrderid, [orderid, productid], (error, values) => {
        if (values) {
            return res.json(values);
        }
        return res.json(error);
    })
})
app.get('/add-order/:username', (req, res) => {
    const username = req.params.username;
    const getInfoCustomer = `SELECT * from user WHERE username=?`;
    db.query(getInfoCustomer, username, (error, info) => {
        if (info) {
            const name = info[0].name;
            const phonenumber = info[0].phonenumber;
            const email = info[0].email;
            const sql = "INSERT INTO `order`(username,name,phonenumber,email,status) VALUES(?,N'" + name + "','" + phonenumber + "','" + email + "','unfinished')";
            db.query(sql, [username], (err, data) => {
                if (err) {
                    return res.json(err);
                }
                const getOrderid = "SELECT * FROM `order` WHERE username=? and status='unfinished'";
                db.query(getOrderid, [username], (error, values) => {
                    if (error) {
                        return res.json(error);
                    }

                    const orderid = values[0].orderid;
                    return res.json({ orderid });
                });
            });
        }
        if (error) {
            return res.json(error);
        }
    })
});
app.post('/add-order-detail', (req, res) => {
    const sql = 'INSERT INTO `orderdetail`(orderid,productid,quantity,price) VALUES(?,?,?,?)';
    const values = [
        req.body.orderid,
        req.body.productid,
        1,
        req.body.price
    ];
    db.query(sql, values, (err, data) => {
        if (data)
            return res.json({
                result: true,
            })
        else
            return res.json({
                result: false
            })
    })
})
app.get('/get-all-orderdetail/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const sql = `SELECT orderid,productid,typeid,categoryid,colorid,memoryid,image, name, product.price, cost, orderdetail.quantity FROM product, orderdetail
    WHERE product.id=orderdetail.productid AND orderid=?`;
    db.query(sql, orderid, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
app.get(`/check-total/:orderid`, (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'SELECT total FROM `order` WHERE orderid = ?';
    db.query(sql, orderid, (err, data) => {
        if (err) {
            return res.json(err);
        }
        return res.json(data);
    })
});
app.get(`/update-product-quantity/:orderid`, (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'SELECT * FROM orderdetail, `order` WHERE orderdetail.orderid=? and `order`.total=0 and orderdetail.orderid=`order`.`orderid`';
    db.query(sql, orderid, (err, data) => {
        if (err) {
            return res.json(err);
        }

        let responseSent = false;

        for (let i = 0; i < data.length; i++) {
            const selectProductQuantity = 'SELECT * FROM product WHERE id=?';
            db.query(selectProductQuantity, data[i].productid, (error, value) => {
                if (error) {
                    if (!responseSent) {
                        responseSent = true;
                        return res.json(error);
                    }
                }

                for (let a = 0; a < value.length; a++) {
                    const newProductQuantity = value[a].quantity - data[i].quantity;
                    const updateNewProductQuantity = 'UPDATE product SET quantity = ? WHERE id = ?';
                    db.query(updateNewProductQuantity, [newProductQuantity, data[i].productid], (er, rs) => {
                        if (er) {
                            if (!responseSent) {
                                responseSent = true;
                                return res.json(er);
                            }
                        } else if (rs) {
                            if (!responseSent) {
                                responseSent = true;
                                return res.json({ update_new_product_quantity: true });
                            }
                        } else {
                            return res.json({ update_new_product_quantity: false });
                        }
                    });
                }
            });
        }
    });
});


app.delete('/delete-cart/:orderid/:productid', (req, res) => {
    const sql = `DELETE FROM orderdetail WHERE orderid=? AND productid=?`;
    const orderid = req.params.orderid;
    const productid = req.params.productid;
    db.query(sql, [orderid, productid], (err, data) => {
        if (data) {
            return res.json({ delete: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ delete: false });
        }

    })
})
app.post('/update-total/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const totalPrice = req.body.totalPrice;
    const sql = 'UPDATE `order` SET total = ? WHERE orderid = ?';
    db.query(sql, [totalPrice, orderid], (err, data) => {
        if (data) {
            return res.json({ updateTotal: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ updateTotal: false });
        }
    });
});
app.get('/delete-total/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'UPDATE `order` SET total = 0 WHERE orderid = ?';
    db.query(sql, orderid, (err, data) => {
        if (data) {
            return res.json({ deletetotal: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ deletetotal: false });
        }
    });
});
app.get('/get-total/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'SELECT * from `order` WHERE orderid=?';
    db.query(sql, orderid, (err, data) => {
        if (data) {
            return res.json(data);
        } return res.json(err);
    });
});
app.get('/order-infor-customer/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const sql = "SELECT * FROM `order` WHERE orderid='" + orderid + "'";
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.post('/order-confirm/:orderid', (req, res) => {
    const orderid = req.params.orderid;
    const sql = "UPDATE `order` SET delivery=?, payment=?, name=?, phonenumber=?, email=?, address=?,status=? WHERE orderid=?";
    const value = [
        req.body.delivery,
        req.body.payment,
        req.body.name,
        req.body.phonenumber,
        req.body.email,
        req.body.address,
        req.body.status
    ];
    db.query(sql, [...value, orderid], (err, data) => {
        if (data) {
            return res.json({ order: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ order: false });
        }
    });
});
app.post(`/update-payment/:orderid`, (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'UPDATE `order` SET payment=?, status=? WHERE orderid=?';
    db.query(sql, [req.body.payment, req.body.status, orderid], (err, data) => {
        if (data) {
            return res.json({ payment: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ payment: false });
        }
    })
})
app.get(`/order-quantity/:username`, (req, res) => {
    const username = req.params.username;
    const sql = 'SELECT COUNT(orderid) as orderQuantity FROM `order` WHERE username=' + "'" + username + "'" + '';
    db.query(sql, (err, data) => {
        if (data) {
            return res.json(data);
        }
        return res.json(err);
    })
})
app.get(`/sum-totalprice/:username`, (req, res) => {
    const username = req.params.username;
    const sql = 'SELECT sum(total) as total FROM `order` WHERE username=' + "'" + username + "'" + '';
    db.query(sql, (err, data) => {
        if (data) {
            return res.json(data);
        }
        return res.json(err);
    })
})
app.get(`/cancel-order/:orderid`, (req, res) => {
    const orderid = req.params.orderid;
    const sql = 'UPDATE `order` SET status=? WHERE orderid=?';
    db.query(sql, ['canceled', orderid], (err, data) => {
        if (data) {
            return res.json({ cancel: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ cancel: false });
        }
    })
})



//Store
app.get('/store/:productid', (req, res) => {
    const productid = req.params.productid;
    const sql = `SELECT storename from store, product_store, product
                WHERE store.storeid=product_store.storeid AND product.id=product_store.productid AND product.id=?`;
    db.query(sql, productid, (err, data) => {
        if (data) {
            return res.json(data);
        }
        if (err) {
            return res.json(err);
        }
    })
})
app.get('/store-quantity/:productid', (req, res) => {
    const productid = req.params.productid;
    const sql = `SELECT COUNT(storename) as storecount from store, product_store, product
                WHERE store.storeid=product_store.storeid AND product.id=product_store.productid AND product.id=?`;
    db.query(sql, productid, (err, data) => {
        if (data) {
            return res.json(data);
        }
        if (err) {
            return res.json(err);
        }
    })
})
app.get('/store-name', (req, res) => {
    const sql = `SELECT * from store ORDER BY storeid`;
    db.query(sql, (err, data) => {
        if (data) {
            return res.json(data);
        }
        if (err) {
            return res.json(err);
        }
    })
})
//General (category,color,memory,ram,type)
app.get('/category', (req, res) => {
    const sql = 'SELECT * FROM category';
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
app.get('/color', (req, res) => {
    const sql = 'SELECT * FROM color';
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
app.get('/memory', (req, res) => {
    const sql = 'SELECT * FROM memory';
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
app.get('/ram', (req, res) => {
    const sql = 'SELECT * FROM ram';
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
app.get('/type', (req, res) => {
    const sql = 'SELECT * FROM type';
    db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});
//Admin
const storageProduct = multer.diskStorage({
    destination: (req, file, cb) => {
        let destinationPath = 'public/images';
        cb(null, destinationPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
});

const uploadProduct = multer({
    storage: storageProduct,
}).single('product');
const getProductImage = (id, callback) => {
    const sql = `SELECT image FROM product WHERE id = ?`;
    db.query(sql, [id], (err, result) => {
        if (err) {
            callback(err, null);
        } else {
            callback(null, result[0].image);
        }
    });
};
app.post('/upload-image/:productid', uploadProduct, (req, res) => {
    let image = req.file.filename;
    if (image !== '') {
        const productid = req.params.productid;
        getProductImage(productid, (err, imagePro) => {
            if (err) {
                return res.json(err);
            }
            if (imagePro) {
                const imagePath = path.join('public/images', imagePro);
                fs.unlink(imagePath, (err) => {
                    if (err) {
                        console.error('Error deleting current image:', err);
                    }
                });
            }
            const sql = `UPDATE product SET image = '` + image + `' WHERE id='` + productid + `'`;
            db.query(sql, (err, data) => {
                if (data) {
                    return res.json({ upload_image: true });
                } else if (err) {
                    return res.json(err);
                } else {
                    return res.json({ upload_image: false });
                }
            })
        })
    }
})
app.post(`/update-product/:productid`, (req, res) => {
    const productid = req.params.productid;
    const values = [
        req.body.name,
        req.body.categoryid,
        req.body.typeid,
        req.body.memoryid,
        req.body.ramid,
        req.body.inch,
        req.body.colorid,
        req.body.quantity,
        req.body.price,
        req.body.cost,
        req.body.screenTechnology,
        req.body.operatingSystem,
        req.body.screenResolution,
        req.body.screenFeature,
        req.body.rearCamera,
        req.body.frontCamera,
        req.body.sim,
        req.body.pin,
        req.body.chipset,
        productid
    ];
    const sql = 'UPDATE product SET name=?, categoryid=?, typeid=?, memoryid=?, ramid=?, inch=?, colorid=?, quantity=?, price=?, cost=?, screenTechnology=?, operatingSystem=?, screenResolution=?, screenFeature=?, rearCamera=?, frontCamera=?, sim=?, pin=?, chipset=? WHERE id = ?';
    db.query(sql, values, (err, data) => {
        if (data) {
            return res.json({ update_product: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ update_product: false });
        }
    })
})
app.post('/add-new-product', uploadProduct, (req, res) => {
    let image = req.file.filename;
    const values = [
        req.body.name,
        req.body.categoryid,
        req.body.typeid,
        req.body.memoryid,
        req.body.ramid,
        req.body.inch,
        req.body.colorid,
        req.body.quantity,
        req.body.price,
        req.body.cost,
        req.body.screenTechnology,
        req.body.operatingSystem,
        req.body.screenResolution,
        req.body.screenFeature,
        req.body.rearCamera,
        req.body.frontCamera,
        req.body.sim,
        req.body.pin,
        req.body.chipset,
        image,
    ];

    const sql = `INSERT INTO product
          (name, categoryid, typeid, memoryid, ramid, inch, colorid, quantity, price, cost, screenTechnology, operatingSystem, screenResolution, screenFeature, rearCamera, frontCamera, sim, pin, chipset, image)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, values, (err, data) => {
        if (data) {
            return res.json({ add_new_product: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ add_new_product: false });
        }
    });
});




app.delete('/delete-product/:productid', (req, res) => {
    const productid = req.params.productid;
    const sql = "DELETE FROM product WHERE id='" + productid + "'";
    db.query(sql, (err, data) => {
        if (data) {
            return res.json({ delete_product: true });
        } else if (err) {
            return res.json(err);
        } else {
            return res.json({ delete_product: false });
        }
    })
})



//Product
app.get(`/product-quantity/:productid`, (req, res) => {
    const productid = req.params.productid;
    const sql = 'SELECT quantity FROM product WHERE id=?';
    db.query(sql, productid, (err, data) => {
        if (data) {
            return res.json(data);
        }
        return res.json(err);
    })
})
app.post(`/search-count`, (req, res) => {
    const value = [
        req.body.value
    ];
    const sql = "SELECT COUNT(id) as count FROM product WHERE name LIKE '" + value + "%' OR name LIKE '%" + value + "' OR name LIKE '%" + value + "%'";
    db.query(sql, (err, data) => {
        if (err) {
            return res.json(err);
        }
        if (data) {
            return res.json(data);
        }
    })
})
app.post('/search-phone', (req, res) => {
    const value = [
        req.body.value
    ];
    const sql = "SELECT product.id,product.colorid, product.name, memory.memoryname,product.memoryid, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image,categoryid, typeid FROM product JOIN memory ON product.memoryid = memory.memoryid JOIN ram ON product.ramid = ram.ramid JOIN color ON product.colorid = color.colorid WHERE name LIKE '" + value + "%' OR name LIKE '%" + value + "' OR name LIKE '%" + value + "%' ORDER BY price DESC";
    db.query(sql, (err, data) => {
        if (err) {
            return res.json(err);
        }
        if (data) {
            return res.json(data);
        }
    })
})
app.get('/phone', (req, res) => {
    const sql = `SELECT category.categoryname,product.chipset,product.pin,product.sim,product.frontCamera,product.rearCamera,product.screenFeature,product.screenResolution,product.operatingSystem,product.screenTechnology,product.ramid,product.quantity,product.id, product.name, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, 
    product.image,product.memoryid,product.typeid,product.categoryid,product.colorid
    FROM product 
    JOIN memory ON product.memoryid = memory.memoryid 
    JOIN ram ON product.ramid = ram.ramid 
    JOIN color ON product.colorid = color.colorid
    JOIN category ON product.categoryid = category.categoryid
    JOIN type ON product.typeid = type.typeid
    ORDER BY id`;
    db.query(sql, (err, data) => {
        if (err)
            return console.log(err);
        return res.json(data);
    })
})
app.get('/phone-sort/:sort', (req, res) => {
    const sort = req.params.sort;
    const sql = `SELECT product.quantity,product.id,product.memoryid,product.colorid,categoryid,typeid, product.name, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image FROM product JOIN memory ON product.memoryid = memory.memoryid JOIN ram ON product.ramid = ram.ramid JOIN color ON product.colorid = color.colorid ORDER BY price ${sort}`;
    db.query(sql, [sort], (err, data) => {
        if (err)
            return console.log(err);
        return res.json(data);
    })
})
app.get('/phone-series/:id', (req, res) => {
    const categoryid = req.params.id;
    const sql = `SELECT product.quantity,id, name, memoryname,ramname, colorname, inch, price, cost, image,product.colorid,categoryid,typeid,product.memoryid
    FROM product, memory,ram, color
    WHERE product.memoryid=memory.memoryid AND product.ramid=ram.ramid AND product.colorid=color.colorid AND categoryid=?`;
    db.query(sql, [categoryid], (err, data) => {
        if (data)
            return res.json(data);
        return res.json([]);

    })
})
app.get('/phone-series-sort/:id/:sort', (req, res) => {
    const categoryid = req.params.id;
    const sort = req.params.sort;
    const sql = `SELECT product.quantity,id, name, memoryname,ramname, colorname, inch, price, cost, image,product.colorid,categoryid,typeid,product.memoryid
    FROM product, memory,ram, color
    WHERE product.memoryid=memory.memoryid AND product.ramid=ram.ramid AND product.colorid=color.colorid AND categoryid=? ORDER BY price ${sort}`;
    db.query(sql, [categoryid], (err, data) => {
        if (data)
            return res.json(data);
        return res.json([]);
    })
})
app.get('/phone-perpage/:page', async (req, res) => {
    const page = req.params.page;
    let pageSize = 12;
    const offset = Math.max((page - 1) * pageSize, 0);
    const sql = `SELECT product.quantity,product.id,product.colorid, product.name, memory.memoryname,product.memoryid, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image,categoryid, typeid
    FROM product
    JOIN memory ON product.memoryid = memory.memoryid
    JOIN ram ON product.ramid = ram.ramid
    JOIN color ON product.colorid = color.colorid
    LIMIT ${pageSize} OFFSET ${offset}`;

    try {
        await db.query(sql, [page], (err, data) => {
            if (data) {
                return res.json(data);
            }
            return res.json(err);
        });
    } catch (error) {
        return res.json(error);
    }
});
app.get('/phonebyid/:id/:typeid/:categoryid/:colorid/:memoryid', async (req, res) => {
    const id = req.params.id;
    const typeid = req.params.typeid;
    const categoryid = req.params.categoryid;
    const colorid = req.params.colorid;
    const memoryid = req.params.memoryid
    const sql = `SELECT product.quantity,product.price,product.id,product.memoryid, product.name,category.categoryname, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image,
    screenTechnology,operatingSystem,screenResolution,screenFeature,rearCamera,frontCamera,sim,pin,chipset,typeid,product.categoryid
    FROM product
    JOIN memory ON product.memoryid = memory.memoryid
    JOIN ram ON product.ramid = ram.ramid
    JOIN color ON product.colorid = color.colorid
    JOIN category ON product.categoryid=category.categoryid
    WHERE product.id=? and product.typeid=? and product.categoryid=? and product.colorid=? and product.memoryid=?`;
    try {
        await db.query(sql, [id, typeid, categoryid, colorid, memoryid], (err, data) => {
            if (data)
                return res.json(data);
            return res.json(err);
        })
    } catch (error) {
        console.log(error);
    }
})
app.get('/phone-memory-price/:typeid/:categoryid/:colorid', async (req, res) => {
    const categoryid = req.params.categoryid;
    const typeid = req.params.typeid;
    const colorid = req.params.colorid;
    const sql = `SELECT product.id,product.memoryid,memoryname, price 
    from product, memory,type 
    WHERE memory.memoryid=product.memoryid AND product.typeid=type.typeid AND product.typeid=? AND categoryid=? AND colorid=?;`;
    await db.query(sql, [typeid, categoryid, colorid], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get('/phone-image-color-price/:typeid/:categoryid/:memoryid', async (req, res) => {
    const categoryid = req.params.categoryid;
    const typeid = req.params.typeid;
    const memoryid = req.params.memoryid;
    const sql = `SELECT product.id,product.colorid,image, colorname, price from product, color,type
    WHERE product.colorid=color.colorid AND product.typeid=type.typeid AND product.typeid=? AND categoryid=? AND memoryid = ?`;
    await db.query(sql, [typeid, categoryid, memoryid], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get('/phone-memoryname/:id', async (req, res) => {
    const id = req.params.id;
    const sql = `SELECT memoryname FROM product,memory WHERE product.memoryid=memory.memoryid AND id=?`;
    await db.query(sql, [id], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get('/phone-colorname/:id', async (req, res) => {
    const id = req.params.id;
    const sql = `SELECT colorname FROM product,color WHERE product.colorid=color.colorid AND id=?`;
    await db.query(sql, [id], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
app.get('/phone-choose-color/:typeid/:categoryid/:memoryname/:colorname', async (req, res) => {
    const typeid = req.params.typeid;
    const categoryid = req.params.categoryid;
    const memoryname = req.params.memoryname;
    const colorname = req.params.colorname;
    const sql = `SELECT product.id,product.memoryid, product.name,category.categoryname, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image,
    screenTechnology,operatingSystem,screenResolution,screenFeature,rearCamera,frontCamera,sim,pin,chipset,typeid,product.categoryid
    FROM product
    JOIN memory ON product.memoryid = memory.memoryid
    JOIN ram ON product.ramid = ram.ramid
    JOIN color ON product.colorid = color.colorid
    JOIN category ON product.categoryid=category.categoryid
    WHERE product.typeid=? and product.categoryid=? and memoryname=? and colorname=N?`;
    await db.query(sql, [typeid, categoryid, memoryname, colorname], (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
})
// app.get('/phone-perpage-series/:id/:page', async (req, res) => {
//     const page = req.params.page;
//     const categoryid = req.params.id;
//     let pageSize = 12;
//     const offset = Math.max((page - 1) * pageSize, 0);
//     const sql = `SELECT product.id, product.name, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image
//     FROM product
//     JOIN memory ON product.memoryid = memory.memoryid
//     JOIN ram ON product.ramid = ram.ramid
//     JOIN color ON product.colorid = color.colorid
//     JOIN category ON product.categoryid=category.categoryid
//     WHERE product.categoryid= ?
//     LIMIT ${pageSize} OFFSET ${offset} `;

//     try {
//         await db.query(sql, [categoryid, page], (err, data) => {
//             if (data) {
//                 return res.json(data);
//             }
//             return res.json(err);
//         });
//     } catch (error) {
//         return res.json(error);
//     }
// });
// app.get('/phone-perpage-sort/:sort/:page', async (req, res) => {
//     const page = req.params.page;
//     const sort = req.params.sort;
//     let pageSize = 12;
//     const offset = Math.max((page - 1) * pageSize, 0);
//     const sql = `SELECT product.id, product.name, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image
//     FROM product
//     JOIN memory ON product.memoryid = memory.memoryid
//     JOIN ram ON product.ramid = ram.ramid
//     JOIN color ON product.colorid = color.colorid
//     JOIN category ON product.categoryid=category.categoryid
//     ORDER BY price ${sort}
//     LIMIT ${pageSize} OFFSET ${offset} `;

//     try {
//         await db.query(sql, [sort, page], (err, data) => {
//             if (data) {
//                 return res.json(data);
//             }
//             return res.json(err);
//         });
//     } catch (error) {
//         return res.json(error);
//     }
// });
// app.get('/phone-perpage-series-sort/:id/:sort/:page', async (req, res) => {
//     const page = req.params.page;
//     const categoryid = req.params.id;
//     const sort = req.params.sort;
//     let pageSize = 12;
//     const offset = Math.max((page - 1) * pageSize, 0);
//     const sql = `SELECT product.id, product.name, memory.memoryname, ram.ramname, color.colorname, product.inch, product.price, product.cost, product.image
//     FROM product
//     JOIN memory ON product.memoryid = memory.memoryid
//     JOIN ram ON product.ramid = ram.ramid
//     JOIN color ON product.colorid = color.colorid
//     JOIN category ON product.categoryid=category.categoryid
//     WHERE product.categoryid= ? ORDER BY price ${sort}
//     LIMIT ${pageSize} OFFSET ${offset} `;

//     try {
//         await db.query(sql, [categoryid, sort, page], (err, data) => {
//             if (data) {
//                 return res.json(data);
//             }
//             return res.json(err);
//         });
//     } catch (error) {
//         return res.json(error);
//     }
// });
app.get('/phone-totalpage', async (req, res) => {
    const sql = 'SELECT COUNT(*) as total FROM product';
    await db.query(sql, (err, data) => {
        if (data)
            return res.json(data);
        return res.json(err);
    })
});








app.listen(1234, () => {
    console.log('http://localhost:1234/phone');
})