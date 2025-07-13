import cron from 'node-cron';
import cloudinary from '../../configs/cloudinary';
import { nodeClient } from '../../configs/redis';
import { getUserModel } from '../../models/user/userSchema';

const TEMP_IMG_KEY = 'temp_image_list';
const Seller = getUserModel('Seller');

class CronJobServices {
  startAllJobs() {
    this.deleteTempImg();
    this.removeSessions();
  }

  deleteTempImg() {
    return cron.schedule(
      '0 0 * * *',
      async () => {
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

        console.log('✅ Scheduled🕒 jobs initialized');
      },
      {
        timezone: 'UTC',
      }
    );
  }

  removeSessions() {
    return cron.schedule(
      '0 0 * * *',
      async () => {
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
      },
      {
        timezone: 'UTC',
      }
    );
  }
}

export const cronJobServices = new CronJobServices();
