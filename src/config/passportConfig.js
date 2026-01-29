import passport from "passport";
import LocalStrategyPkg from "passport-local";
const LocalStrategy = LocalStrategyPkg.Strategy;
import bcrypt from "bcrypt";
import User from "../models/User.js";

passport.use(new LocalStrategy(
  async(username, password, done) => {
    try {
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return done(null, false, {message: "User not Found"});
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            return done(null, user);
        }
        else return done(null, false, {message: "Incorrect Password"});
    } catch (error) {
        return done(error);
    } 
 }
)); 

 