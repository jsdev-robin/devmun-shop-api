import passport from 'passport';
import config from '../../configs/config';
import {
  GoogleCallbackParameters,
  Strategy as GoogleStrategy,
  Profile,
  VerifyCallback,
} from 'passport-google-oauth20';

const strategiesConfig = {
  google: {
    clientID: config.GOOGLE_CLIENT_ID,
    clientSecret: config.GOOGLE_CLIENT_SECRET,
    callbackURL: config.ISPRODUCTION
      ? 'https://api.devmun.xyz/v1/dashboard/user/auth/google/callback'
      : 'http://localhost:8080/v1/dashboard/user/auth/google/callback',
  },
};

const handleOAuth = async (
  accessToken: string,
  refreshToken: string,
  params: GoogleCallbackParameters,
  profile: Profile,
  done: VerifyCallback
): Promise<void> => {
  return done(null, profile);
};

const initializePassport = async (): Promise<void> => {
  passport.use(new GoogleStrategy(strategiesConfig.google, await handleOAuth));
};

export { initializePassport, passport };
