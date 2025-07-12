import { Request, Response } from 'express';
import cloudinary from '../../configs/cloudinary';
import { nodeClient } from '../../configs/redis';
import { catchAsync } from '../../libs/catchAsync';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';

const TEMP_IMG_KEY = 'temp_image_list';

export class UtilsServices {
  public setTempImg = catchAsync(
    async (req: Request, res: Response): Promise<void> => {
      const { publicId } = req.body;

      const p = nodeClient.multi();
      p.SADD(TEMP_IMG_KEY, publicId);
      p.EXPIRE(TEMP_IMG_KEY, 3 * 24 * 60 * 60);
      await p.exec();

      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message: 'Temporary image stored successfully.',
      });

      res.on('finish', () => {
        console.log('Client received response, now processing...');
      });
    }
  );

  public deleteTempImg = catchAsync(
    async (_req: Request, res: Response): Promise<void> => {
      const publicIds = await nodeClient.SMEMBERS(TEMP_IMG_KEY);

      const results = await Promise.allSettled(
        publicIds.map((publicId) =>
          cloudinary.uploader
            .destroy(publicId, { invalidate: true })
            .then((res) => ({
              publicId,
              success: res.result === 'ok',
            }))
        )
      );

      const deleted: string[] = [];
      const failed: string[] = [];

      const p = nodeClient.multi();

      results.forEach((result) => {
        if (result.status === 'fulfilled') {
          if (result.value.success) {
            deleted.push(result.value.publicId);
            p.SREM(TEMP_IMG_KEY, result.value.publicId);
          } else {
            failed.push(result.value.publicId);
          }
        } else {
          failed.push('unknown');
        }
      });

      await p.exec();

      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Cloudinary images deletion completed. Redis updated.',
        deleted,
        failed,
        remaining: await nodeClient.SMEMBERS(TEMP_IMG_KEY),
      });
    }
  );
}
