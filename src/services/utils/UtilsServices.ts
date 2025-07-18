import { NextFunction, Request, Response } from 'express';
import cloudinary from '../../configs/cloudinary';
import { nodeClient } from '../../configs/redis';
import { catchAsync } from '../../libs/catchAsync';
import ApiError from '../../middlewares/errors/ApiError';
import { getUserModel } from '../../models/user/userSchema';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';

const TEMP_IMG_KEY = 'temp_image_list';
const Seller = getUserModel('Seller');

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

  public deleteTempImgById = catchAsync(
    async (req: Request, res: Response, next: NextFunction) => {
      const { id } = req.params;

      const results = await Promise.allSettled([
        cloudinary.uploader.destroy(id, {
          resource_type: 'image',
          invalidate: true,
        }),
        cloudinary.uploader.destroy(id, {
          resource_type: 'video',
          invalidate: true,
        }),
      ]);

      const deleted = results.some(
        (r) => r.status === 'fulfilled' && r.value.result === 'ok'
      );

      if (!deleted) {
        return next(new ApiError('Asset not found', 404));
      }

      await nodeClient.SREM(TEMP_IMG_KEY, id);

      res.status(200).json({
        status: 'success',
        message: `Asset "${id}" deleted`,
      });
    }
  );

  public removeAlSessions = catchAsync(async (req: Request, res: Response) => {
    const now = new Date();
    const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);

    const userInfo = await Seller.find(
      {
        'sessions.loggedInAt': {
          $lt: threeDaysAgo,
        },
      },
      { id: 1, 'sessions.token': 1, 'sessions.loggedInAt': 1 }
    ).lean();

    await Promise.all(
      userInfo.map(async (user) => {
        await Promise.all(
          (user.sessions || []).map((sesions) => {
            const p = nodeClient.multi();
            p.SREM(`${user._id}:session`, String(sesions.token));
            p.json.del(String(user._id));
            return p.exec();
          })
        );

        return Seller.updateOne(
          { _id: user._id },
          {
            $pull: {
              sessions: {
                loggedInAt: { $lt: threeDaysAgo },
              },
            },
          }
        );
      })
    );

    res.status(200).json({
      status: 'success',
      userInfo,
    });
  });
}
