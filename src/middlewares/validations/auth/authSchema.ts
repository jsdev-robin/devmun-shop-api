import { check, query } from 'express-validator';

export const authSchema = {
  //  Account Registration
  signup: [
    check('firstName')
      .trim()
      .notEmpty()
      .withMessage('First name is required')
      .isLength({ min: 2, max: 32 })
      .withMessage('Must be 2-32 characters')
      .custom(
        (value) => value.charAt(0).toUpperCase() + value.slice(1).toLowerCase()
      )
      .escape(),

    check('lastName')
      .trim()
      .notEmpty()
      .withMessage('Last name is required')
      .isLength({ min: 2, max: 32 })
      .withMessage('Must be 2-32 characters')
      .custom(
        (value) => value.charAt(0).toUpperCase() + value.slice(1).toLowerCase()
      )
      .escape(),

    check('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Please enter a valid email'),

    check('password')
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ min: 8 })
      .withMessage('Must be at least 8 characters')
      .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/)
      .withMessage(
        'Must contain uppercase, lowercase, number, and special character'
      ),

    check('passwordConfirm')
      .notEmpty()
      .withMessage('Please confirm your password')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match'),
  ],

  // Email Verification
  verifyEmail: [
    check('otp')
      .notEmpty()
      .withMessage('Verification code is required')
      .isNumeric()
      .withMessage('Code must be numeric')
      .isLength({ min: 6, max: 6 })
      .withMessage('Must be 6 digits'),
    check('token').notEmpty().withMessage('Session token is required'),
  ],

  // User Login
  signin: [
    check('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Please enter a valid email'),
    check('password').notEmpty().withMessage('Password is required'),
    check('remember').optional().toBoolean(),
  ],

  // Password Management
  updatePassword: [
    check('currentPassword')
      .notEmpty()
      .withMessage('Current password is required'),

    check('newPassword')
      .notEmpty()
      .withMessage('New password is required')
      .isLength({ min: 8 })
      .withMessage('Must be at least 8 characters')
      .matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/)
      .withMessage(
        'Must contain uppercase, lowercase, number, and special character'
      )
      .custom((value, { req }) => value !== req.body.currentPassword)
      .withMessage('New password must be different from current'),

    check('confirmNewPassword')
      .notEmpty()
      .withMessage('Please confirm your new password')
      .custom((value, { req }) => value === req.body.newPassword)
      .withMessage('Passwords do not match'),
  ],

  // Email Management
  updateEmail: [
    check('newEmail')
      .trim()
      .notEmpty()
      .withMessage('New email is required')
      .isEmail()
      .withMessage('Please enter a valid email'),

    check('confirmEmail')
      .trim()
      .notEmpty()
      .withMessage('Please confirm your email')
      .isEmail()
      .withMessage('Please enter a valid email')
      .custom((value, { req }) => value === req.body.newEmail)
      .withMessage('Emails do not match')
      .custom((value, { req }) => value !== req.self?.email)
      .withMessage('New email must be different from current email'),

    check('password')
      .notEmpty()
      .withMessage('Password is required for verification'),
  ],

  updatingEmail: [
    query('token').trim().notEmpty().withMessage('Token is required'),
  ],

  // User Preferences
  updateSettings: [
    // Location settings (all optional)
    check('location.region')
      .optional()
      .trim()
      .isString()
      .withMessage('Region must be a valid text value')
      .isLength({ max: 100 })
      .withMessage('Region cannot exceed 100 characters'),

    check('location.language')
      .optional()
      .trim()
      .isString()
      .withMessage('Language must be a valid text value')
      .isLength({ max: 50 })
      .withMessage('Language cannot exceed 50 characters'),

    check('location.currency')
      .optional()
      .trim()
      .isString()
      .withMessage('Currency must be a valid text value')
      .isLength({ max: 10 })
      .withMessage('Currency code cannot exceed 10 characters')
      .isUppercase()
      .withMessage('Currency code must be in uppercase'),

    // Communication preferences (optional booleans)
    check('communication.postalMail')
      .optional()
      .isBoolean()
      .withMessage('Postal mail preference must be either true or false')
      .toBoolean(),

    check('communication.phoneCalls')
      .optional()
      .isBoolean()
      .withMessage('Phone calls preference must be either true or false')
      .toBoolean(),

    // Notification settings (optional booleans)
    check('notifications.send_message')
      .optional()
      .isBoolean()
      .withMessage('Message sending notification must be true or false')
      .toBoolean(),

    check('notifications.receive_reply')
      .optional()
      .isBoolean()
      .withMessage('Reply receipt notification must be true or false')
      .toBoolean(),

    check('notifications.new_follower')
      .optional()
      .isBoolean()
      .withMessage('New follower notification must be true or false')
      .toBoolean(),

    check('notifications.listing_expiration')
      .optional()
      .isBoolean()
      .withMessage('Listing expiration notification must be true or false')
      .toBoolean(),

    // Subscription preferences (optional booleans)
    check('subscriptions.new_notable')
      .optional()
      .isBoolean()
      .withMessage('New notable items subscription must be true or false')
      .toBoolean(),

    check('subscriptions.feedback')
      .optional()
      .isBoolean()
      .withMessage('Feedback subscription must be true or false')
      .toBoolean(),

    check('subscriptions.coupons_promotions')
      .optional()
      .isBoolean()
      .withMessage('Coupons and promotions subscription must be true or false')
      .toBoolean(),

    check('subscriptions.forums')
      .optional()
      .isBoolean()
      .withMessage('Forums subscription must be true or false')
      .toBoolean(),

    check('subscriptions.advocacy')
      .optional()
      .isBoolean()
      .withMessage('Advocacy subscription must be true or false')
      .toBoolean(),

    check('subscriptions.seller_activity')
      .optional()
      .isBoolean()
      .withMessage('Seller activity subscription must be true or false')
      .toBoolean(),

    check('subscriptions.news_features')
      .optional()
      .isBoolean()
      .withMessage('News and features subscription must be true or false')
      .toBoolean(),

    check('subscriptions.shop_tips')
      .optional()
      .isBoolean()
      .withMessage('Shop tips subscription must be true or false')
      .toBoolean(),

    check('subscriptions.pattern_news')
      .optional()
      .isBoolean()
      .withMessage('Pattern news subscription must be true or false')
      .toBoolean(),

    check('subscriptions.premium_news')
      .optional()
      .isBoolean()
      .withMessage('Premium news subscription must be true or false')
      .toBoolean(),
  ],

  // Public profile
  profile: [
    check('firstName')
      .optional()
      .isString()
      .withMessage('First name must be a string')
      .trim()
      .isLength({ max: 50 })
      .withMessage('First name max length is 50 characters'),
    check('lastName')
      .optional()
      .isString()
      .withMessage('Last name must be a string')
      .trim()
      .isLength({ max: 50 })
      .withMessage('Last name max length is 50 characters'),
    check('gender')
      .optional()
      .isIn(['male', 'female', 'other', 'prefer-not-to-say'])
      .withMessage(
        'Gender must be one of male, female, other, prefer-not-to-say'
      ),
    check('city').optional().isString().withMessage('City must be a string'),
    check('birthday')
      .optional()
      .isISO8601()
      .withMessage('Birthday must be a valid ISO date (YYYY-MM-DD)')
      .toDate(),
    check('about').optional().isString().withMessage('About must be a string'),
    check('favoriteMaterials')
      .optional()
      .isArray({ max: 13 })
      .withMessage('favoriteMaterials must be an array with maximum 13 items'),
    check('favoriteMaterials.*')
      .isString()
      .withMessage('Each favorite material must be a string'),
    check('includeOnProfile')
      .optional()
      .isBoolean()
      .withMessage('IncludeOnProfile must be a boolean'),
    check('include')
      .optional()
      .isObject()
      .withMessage('Include must be an object'),
  ],

  // get Field

  getFields: [
    check('mun')
      .optional({ nullable: true })
      .isString()
      .withMessage('mun must be a string'),
    query('fields')
      .trim()
      .notEmpty()
      .withMessage('Fields is required')
      .isString()
      .withMessage('Fields must be a string'),
  ],

  // address
  address: [
    check('country')
      .trim()
      .notEmpty()
      .withMessage('Country is required')
      .isString()
      .withMessage('Country must be a string'),

    check('fullName')
      .trim()
      .notEmpty()
      .withMessage('Full name is required')
      .isString()
      .withMessage('Full name must be a string'),

    check('street')
      .trim()
      .notEmpty()
      .withMessage('Street address is required')
      .isString()
      .withMessage('Street must be a string'),

    check('city')
      .trim()
      .notEmpty()
      .withMessage('City is required')
      .isString()
      .withMessage('City must be a string'),

    // Optional fields
    check('flat')
      .optional()
      .trim()
      .isString()
      .withMessage('Flat must be a string'),

    check('postCode')
      .optional()
      .trim()
      .isString()
      .withMessage('Post code must be a string'),

    check('isDefault')
      .optional()
      .isBoolean()
      .withMessage('isDefault must be true or false')
      .toBoolean(),
  ],

  // Feedback
  feedback: [
    check('reason')
      .trim()
      .notEmpty()
      .withMessage('Please select a reason')
      .isString()
      .withMessage('Reason must be a string'),

    // Optional fields
    check('subreason')
      .optional()
      .trim()
      .isString()
      .withMessage('Subreason must be a string'),

    check('description')
      .optional()
      .trim()
      .isString()
      .withMessage('Description must be a string')
      .isLength({ max: 500 })
      .withMessage('Description cannot exceed 500 characters'),

    check('contractEmail')
      .optional()
      .isBoolean()
      .withMessage('contractEmail must be true or false')
      .toBoolean(),
  ],
};
