import mongoose from 'mongoose';

const orderSchema = new mongoose.Schema({
  customerName: {
    type: String,
    required: true,
    trim: true
  },
  customerPhone: {
    type: String,
    required: true,
    trim: true
  },
  customerEmail: {
    type: String,
    required: false,
    trim: true
  },
  designerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  designerName: {
    type: String,
    required: false
  },
  orderType: {
    type: String,
    enum: ['custom-design', 'ready-made'],
    default: 'custom-design'
  },
  sareeType: {
    type: String,
    required: true,
    trim: true
  },
  material: {
    type: String,
    required: true,
    trim: true
  },
  color: {
    type: String,
    required: true,
    trim: true
  },
  design: {
    type: String,
    required: true,
    trim: true
  },
  // Measurements (simplified as single text field)
  measurements: {
    type: String,
    required: false,
    trim: true
  },
  // Order dates
  orderPlacedDate: {
    type: Date,
    default: Date.now
  },
  expectedDeliveryDate: {
    type: Date,
    required: true
  },
  actualDeliveryDate: {
    type: Date
  },
  // Payment details
  paymentMethod: {
    type: String,
    enum: ['cash', 'online'],
    required: true
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'completed', 'failed', 'paymentSuccessful'],
    default: 'pending'
  },
  amount: {
    type: Number,
    required: true
  },
  advanceAmount: {
    type: Number,
    default: 0
  },
  balanceAmount: {
    type: Number,
    default: 0
  },
  // UPI payment details
  upiTransactionId: {
    type: String
  },
  upiPaymentProof: {
    type: String // URL to payment screenshot
  },
  // Order status
  status: {
    type: String,
    enum: ['pending', 'in-progress', 'ready', 'delivered', 'cancelled'],
    default: 'pending'
  },
  // Additional details
  specialInstructions: {
    type: String,
    trim: true
  },
  fabricSwatch: {
    type: String // URL to fabric swatch image
  },
  designSketch: {
    type: String // URL to design sketch image
  },
  // Progress tracking
  progressUpdates: [{
    date: {
      type: Date,
      default: Date.now
    },
    status: {
      type: String,
      required: true
    },
    description: {
      type: String,
      required: true
    },
    updatedBy: {
      type: String,
      required: true
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field before saving
orderSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Calculate balance amount
orderSchema.pre('save', function(next) {
  if (this.amount && this.advanceAmount) {
    this.balanceAmount = this.amount - this.advanceAmount;
  }
  next();
});

export default mongoose.model('Order', orderSchema);
