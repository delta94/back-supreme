const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const nodemailer = require("nodemailer");
const { hasPermission } = require("../utils");
const { transport, makeANiceEmail } = require("../mail");
const stripe = require("../stripe");

const Mutations = {
  createItem: async (parent, args, ctx, info) => {
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }

    const item = await ctx.db.mutation.createItem(
      { data: { ...args, user: { connect: { id: ctx.request.userId } } } },
      info
    );

    return item;
  },
  updateItem: async (parent, args, ctx, info) => {
    const updates = { ...args };
    delete updates.id;

    return await ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  deleteItem: async (parent, args, ctx, info) => {
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title user { id }}`);
    // 2. Check if they own that item, or have the permissions
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ["ADMIN", "ITEMDELETE"].includes(permission)
    );

    if (!ownsItem && !hasPermissions) {
      throw new Error("You don't have permission to do that!");
    }

    // 3. Delete it!
    return await ctx.db.mutation.deleteItem({ where }, info);
  },
  signup: async (parent, args, ctx, info) => {
    args.email = args.email.toLowerCase();

    const password = await bcrypt.hash(args.password, 10);

    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] }
        }
      },
      info
    );

    const token = await jwt.sign({ userId: user.id }, process.env.APP_SECRET);

    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });

    return user;
  },
  signin: async (parent, { email, password }, ctx, info) => {
    const user = await ctx.db.query.user({ where: { email } });

    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      throw new Error("Invalid Password!");
    }

    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);

    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });

    return user;
  },
  signout: async (parent, args, ctx, info) => {
    ctx.response.clearCookie("token");
    return { message: "Goodbye!" };
  },
  requestReset: async (parent, args, ctx, info) => {
    const user = await ctx.db.query.user({ where: { email: args.email } });

    if (!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }

    const randomBytesPromiseified = promisify(randomBytes);
    const resetToken = (await randomBytesPromiseified(20)).toString("hex");

    const resetTokenExpiry = Date.now() + 3600000;

    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    });

    // console.log(res);
    const mailRes = await transport.sendMail({
      from: "datfc97pro@gmail.com",
      to: user.email,
      subject: "Your Password Reset Token",
      html: makeANiceEmail(`Your Password Reset Token is here!
      \n\n
      <a href="${
        process.env.FRONTEND_URL
      }/reset?resetToken=${resetToken}">Click Here to Reset</a>`)
    });

    return { message: "Thanks" };
  },
  resetPassword: async (parent, args, ctx, info) => {
    if (args.password !== args.confirmPassword) {
      throw new Error(`Yo Password don\'t match!`);
    }

    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    });

    if (!user) {
      throw new Error("This token is either invalid or expired!");
    }

    const password = await bcrypt.hash(args.password, 10);

    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    });

    const token = await jwt.sign(
      { userId: updatedUser.id },
      process.env.APP_SECRET
    );

    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });

    return updatedUser;
  },
  updatePermissions: async (parent, args, ctx, info) => {
    if (!ctx.request.userId) {
      throw new Error(`You must be logged in!`);
    }

    const currentUser = await ctx.db.query.user(
      { where: { id: ctx.request.userId } },
      info
    );

    hasPermission(currentUser, ["ADMIN", "PERMISSIONUPDATE"]);

    return await ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions
          }
        },
        where: { id: args.userId }
      },
      info
    );
  },
  addToCart: async (parent, args, ctx, info) => {
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in soooon");
    }
    // 2. Query the users current cart
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    });
    // 3. Check if that item is already in their cart and increment by 1 if it is
    if (existingCartItem) {
      return await ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: { quantity: existingCartItem.quantity + 1 }
        },
        info
      );
    }
    // 4. If its not, create a fresh CartItem for that user!
    return await ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId }
          },
          item: {
            connect: { id: args.id }
          }
        }
      },
      info
    );
  },
  removeFromCart: async (parent, args, ctx, info) => {
    const cartItem = await ctx.db.query.cartItem(
      {
        where: { id: args.id }
      },
      `{ id user { id } }`
    );

    if (!cartItem) throw new Error(`No CartItem Found!`);

    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error(`Cheatin huhhhh`);
    }

    return await ctx.db.mutation.deleteCartItem(
      {
        where: {
          id: args.id
        }
      },
      info
    );
  },
  createOrder: async (parent, args, ctx, info) => {
    const { userId } = ctx.request;

    if (!userId)
      throw new Error(`You must be signed in to complete this order.`);

    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{ id name email cart { id quantity item { title price id description image largeImage } } }`
    );

    const amount = user.cart.reduce(
      (item1, item2) => item1 + item2.item.price * item2.quantity,
      0
    );

    const charge = await stripe.charges.create({
      amount,
      currency: "USD",
      source: args.token
    });

    const orderItems = user.cart.map(item => {
      const orderItem = {
        ...item.item,
        quantity: item.quantity,
        user: { connect: { id: userId } }
      };

      delete orderItem.id;
      return orderItem;
    });

    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } }
      }
    });

    const cartItemIds = user.cart.map(item => item.id);

    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds
      }
    });

    return order;
  }
};

module.exports = Mutations;
