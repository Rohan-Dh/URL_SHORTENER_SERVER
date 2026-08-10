import { Router } from 'express';
import shortUrlController from '../controllers/shortUrl.controller.js';

const router = Router();

router.post('/shorten', shortUrlController.create);
router.get('/shorten/:shortCode', shortUrlController.stats);
router.get('/shorten/:shortCode/analytics', shortUrlController.analytics);
router.get('/me/links', shortUrlController.myLinks);

export default router;
