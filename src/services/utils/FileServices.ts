import { UploadApiOptions, UploadApiResponse } from 'cloudinary';
import cloudinary from '../../configs/cloudinary';

export class FileServices {
  static uploadImage = async (
    publicId: string,
    filePath: string,
    options: Partial<UploadApiOptions> = {}
  ): Promise<UploadApiResponse> => {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: 'general',
      public_id: publicId,
      use_filename: true,
      unique_filename: false,
      overwrite: true,
      resource_type: 'image',
      ...options,
    });

    return result;
  };
}
