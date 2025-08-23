import mongoose from 'mongoose';

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    required: true,
    enum: ['silk', 'cotton', 'georgette', 'crepe', 'chiffon', 'satin', 'jacquard', 'embroidery', 'printed', 'bridal', 'party-wear', 'casual']
  },
  image: {
    type: String,
    required: true
  },
  shortDescription: {
    type: String,
    required: true,
    maxlength: 200
  },
  fullDescription: {
    type: String,
    required: true
  },
  features: [{
    type: String
  }],
  price: {
    type: Number,
    required: true
  },
  originalPrice: {
    type: Number
  },
  discount: {
    type: Number,
    default: 0
  },
  inStock: {
    type: Boolean,
    default: true
  },
  sizes: [{
    type: String,
    enum: ['XS', 'S', 'M', 'L', 'XL', 'XXL', 'Free Size']
  }],
  colors: [{
    type: String
  }],
  material: {
    type: String,
    required: true
  },
  blouseLength: {
    type: String
  },
  sareeLength: {
    type: String
  },
  careInstructions: [{
    type: String
  }],
  tags: [{
    type: String
  }],
  rating: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  },
  reviewCount: {
    type: Number,
    default: 0
  },
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
productSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.model('Product', productSchema);
