import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const validateDocument = [
  body('documentTitle')
    .isLength({ min: 3, max: 100 })
    .withMessage('Document title must be between 3 and 100 characters')
    .trim()
    .escape(),
  
  body('physicalLocation.locationType')
    .notEmpty()
    .withMessage('Location type is required')
    .isIn(['Shelf', 'Cabinet', 'Box', 'Folder'])
    .withMessage('Invalid location type'),
  
  body('physicalLocation.locationId')
    .notEmpty()
    .withMessage('Location ID is required')
    .trim()
    .escape(),
  
  body('physicalLocation.floor')
    .notEmpty()
    .withMessage('Floor is required')
    .trim()
    .escape(),
  
  body('physicalLocation.additionalInfo')
    .optional()
    .trim()
    .escape(),
  
  body('documentType')
    .isIn(['DIGITAL_ONLY', 'PHYSICAL_ONLY', 'BOTH'])
    .withMessage('Invalid document type'),
];

export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};