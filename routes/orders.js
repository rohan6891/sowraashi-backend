import express from 'express';
import jwt from 'jsonwebtoken';
import Order from '../models/Order.js';
import upload from '../middleware/upload.js';
import dotenv from 'dotenv';
import mongoose from 'mongoose'; 
const router = express.Router();

dotenv.config({ path: '.env.production' });

// Create custom order (no authentication required)
router.post('/custom', async (req, res) => {
  try {
    const {
      name,
      mobile,
      designDescription,
      totalBill,
      advancePayment,
      paymentMethod,
      paymentStatus,
      presentDate,
      deliveryDate
    } = req.body;

    // Validate required fields
    if (!name || !mobile || !designDescription || !totalBill || !paymentMethod || !presentDate || !deliveryDate) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Create order object
    const orderData = {
      customerName: name,
      customerPhone: mobile,
      design: designDescription,
      amount: parseFloat(totalBill),
      advanceAmount: advancePayment ? parseFloat(advancePayment) : 0,
      paymentMethod: paymentMethod,
      paymentStatus: paymentStatus || 'pending',
      orderPlacedDate: new Date(presentDate),
      expectedDeliveryDate: new Date(deliveryDate),
      status: 'pending',
      orderType: 'custom-design',
      sareeType: 'Custom Design',
      material: 'As per design',
      color: 'As per design'
    };

    const order = new Order(orderData);
    await order.save();

    res.status(201).json({
      message: 'Custom order created successfully',
      order
    });

  } catch (error) {
    console.error('Create custom order error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  console

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check if user is designer or admin
const requireDesignerOrAdmin = (req, res, next) => {
  if (req.user.role !== 'designer' && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Designer or admin access required' });
  }
  next();
};

// Create new order (designer only)
router.post('/', authenticateToken, requireDesignerOrAdmin, upload.fields([
  { name: 'fabricSwatch', maxCount: 1 },
  { name: 'designSketch', maxCount: 1 },
  { name: 'upiPaymentProof', maxCount: 1 }
]), async (req, res) => {
  try {
    const {
      customerName,
      customerPhone,
      customerEmail,
      sareeType,
      material,
      color,
      design,
      measurements,
      expectedDeliveryDate,
      paymentMethod,
      amount,
      advanceAmount,
      specialInstructions
    } = req.body;

    // Create order object
    const orderData = {
      customerName,
      customerPhone,
      customerEmail,
      designerId: req.user.userId,
      designerName: req.user.name,
      sareeType,
      material,
      color,
      design,
      measurements,
      expectedDeliveryDate: new Date(expectedDeliveryDate),
      paymentMethod,
      amount: parseFloat(amount),
      advanceAmount: advanceAmount ? parseFloat(advanceAmount) : 0,
      specialInstructions
    };

    // Handle file uploads
    if (req.files) {
      if (req.files.fabricSwatch) {
        orderData.fabricSwatch = `/uploads/${req.files.fabricSwatch[0].filename}`;
      }
      if (req.files.designSketch) {
        orderData.designSketch = `/uploads/${req.files.designSketch[0].filename}`;
      }
      if (req.files.upiPaymentProof) {
        orderData.upiPaymentProof = `/uploads/${req.files.upiPaymentProof[0].filename}`;
      }
    }

    const order = new Order(orderData);
    await order.save();

    res.status(201).json({
      message: 'Order created successfully',
      order
    });

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all orders (admin can see all, designer can see their own)
router.get('/', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;

    let query = {};

    console.log("received request");

    // Designer can only see their own orders
    if (req.user.role === 'designer') {
      query.designerId = req.user.userId;
    }

    // Filter by status
    if (req.user.role === 'designer') {
      query.designerId = {
        $in: [new mongoose.Types.ObjectId(req.user.userId), null]
      };
    }

    // Pagination
    const skip = (page - 1) * limit;

    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('designerId', 'name username');

    console.log(orders);

    const total = await Order.countDocuments(query);

    res.json({
      orders,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalOrders: total,
        hasNextPage: page * limit < total,
        hasPrevPage: page > 1
      }
    });

  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get single order
router.get('/:id', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('designerId', 'name username');

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Designer can only access their own orders
    if (req.user.role === 'designer' && order.designerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(order);

  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update order status
router.patch('/:id/status', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const { status, description } = req.body;

    if (!status || !description) {
      return res.status(400).json({ message: 'Status and description are required' });
    }

    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Designer can only update their own orders
    if (req.user.role === 'designer' && order.designerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Add progress update
    order.progressUpdates.push({
      status,
      description,
      updatedBy: req.user.name
    });

    // Update main status
    order.status = status;

    // Update delivery date if status is 'delivered'
    if (status === 'delivered') {
      order.actualDeliveryDate = new Date();
    }

    await order.save();

    res.json({
      message: 'Order status updated successfully',
      order
    });

  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update payment status
router.patch('/:id/payment', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const { paymentStatus, upiTransactionId } = req.body;

    if (!paymentStatus) {
      return res.status(400).json({ message: 'Payment status is required' });
    }

    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Designer can only update their own orders
    if (req.user.role === 'designer' && order.designerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    order.paymentStatus = paymentStatus;
    if (upiTransactionId) {
      order.upiTransactionId = upiTransactionId;
    }

    await order.save();

    res.json({
      message: 'Payment status updated successfully',
      order
    });

  } catch (error) {
    console.error('Update payment status error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update payment status (alternative endpoint for admin dashboard)
router.patch('/:id/payment-status', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const { paymentStatus } = req.body;

    if (!paymentStatus) {
      return res.status(400).json({ message: 'Payment status is required' });
    }

    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Designer can only update their own orders (but custom orders don't have designerId)
    if (req.user.role === 'designer' && order.designerId && order.designerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    order.paymentStatus = paymentStatus;
    await order.save();

    res.json({
      message: 'Payment status updated successfully',
      order
    });

  } catch (error) {
    console.error('Update payment status error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update order details
router.put('/:id', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Designer can only update their own orders
    if (req.user.role === 'designer' && order.designerId.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Update allowed fields
    const updateFields = [
      'customerName', 'customerPhone', 'customerEmail', 'sareeType', 'material',
      'color', 'design', 'expectedDeliveryDate', 'amount', 'advanceAmount',
      'specialInstructions'
    ];

    updateFields.forEach(field => {
      if (req.body[field] !== undefined) {
        order[field] = req.body[field];
      }
    });

    // Update measurements if provided
    if (req.body.measurements) {
      Object.keys(req.body.measurements).forEach(key => {
        if (req.body.measurements[key] !== undefined) {
          order.measurements[key] = parseFloat(req.body.measurements[key]);
        }
      });
    }

    await order.save();

    res.json({
      message: 'Order updated successfully',
      order
    });

  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete order (admin only)
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const order = await Order.findByIdAndDelete(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    res.json({ message: 'Order deleted successfully' });

  } catch (error) {
    console.error('Delete order error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get order statistics
router.get('/stats/overview', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    let query = {};

    // Designer can only see their own stats
    if (req.user.role === 'designer') {
      query.designerId = req.user.userId;
    }

    const stats = await Order.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalAmount: { $sum: '$amount' },
          pendingOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          inProgressOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] }
          },
          readyOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'ready'] }, 1, 0] }
          },
          deliveredOrders: {
            $sum: { $cond: [{ $eq: ['$status', 'delivered'] }, 1, 0] }
          }
        }
      }
    ]);

    res.json(stats[0] || {
      totalOrders: 0,
      totalAmount: 0,
      pendingOrders: 0,
      inProgressOrders: 0,
      readyOrders: 0,
      deliveredOrders: 0
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update payment status to successful (designer only)
router.patch('/:id/payment-success', authenticateToken, requireDesignerOrAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Update payment status
    order.paymentStatus = 'paymentSuccessful';
    await order.save();

    res.json({
      message: 'Payment status updated successfully',
      order
    });

  } catch (error) {
    console.error('Update payment status error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

export default router;
