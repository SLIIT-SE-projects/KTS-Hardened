const Bus = require("../models/busModel");
const asyncHandler = require("express-async-handler");
const cloudinary = require("cloudinary").v2;
const fs = require("fs");
const { fileSizeFormatter } = require("../util/fileUpload");
const { allow } = require("../util/rateGate");

//create bus
const createBus = asyncHandler(async (req, res) => {

  const key = req.user?.id ? `u:${req.user.id}` : `ip:${req.ip}`;
  const decision = allow({
    key,
    max: Number(process.env.RATE_CREATE_MAX || 20),
    windowMs: Number(process.env.RATE_WINDOW_MS || 15 * 60 * 1000),
  });
  if (!decision.allowed) {
    res.set("RateLimit-Limit", String(process.env.RATE_CREATE_MAX || 20));
    res.set("RateLimit-Remaining", String(decision.remaining));
    res.set("RateLimit-Reset", Math.ceil(decision.resetAt / 1000).toString());
    return res.status(429).json({ error: "Too many create requests. Please try again later." });
  }

  const personType = req.personType;

  if (personType === "user") {
    res.status(401);
    throw new Error("Not authorized , Please login as a manager");
  }

  const {
    busId,
    registrationNumber,
    chassisNumber,
    model,
    seatingCapacity,
    color,
    driver,
    conductor,
    owner,
  } = req.body;

  //validate
  if (
    !busId ||
    !registrationNumber ||
    !chassisNumber ||
    !model ||
    !seatingCapacity ||
    !color ||
    !driver ||
    !conductor ||
    !owner
  ) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(400);
    throw new Error("Please fill all the fields");
  }

  //Manage image upload
  let fileData = {};
  let uploadedFile;

  if (req.file) {
    //upload
    try {
      uploadedFile = await cloudinary.uploader.upload(req.file.path, {
        folder: "KTS/buses",
        resource_type: "image",
      });
    } catch (err) {
      res.status(500);
      throw new Error("Image could not be uploaded");
    }

    fileData = {
      fileName: req.file.originalname,
      filePath: uploadedFile.secure_url,
      fileType: req.file.mimetype,
      fileSize: fileSizeFormatter(req.file.size, 2),
      fileID: uploadedFile.public_id,
    };

    //delete file from uploads folder
    fs.unlinkSync(req.file.path);
  }

  try {
    const bus = await Bus.create({
      busId,
      registrationNumber,
      chassisNumber,
      model,
      seatingCapacity,
      color,
      driver,
      conductor,
      owner,
      photo: fileData,
    });

    if (bus) {
      res.status(201).json(bus);
    } else {
      if (fileData.filePath) {
        await cloudinary.uploader.destroy(uploadedFile.public_id);
      }
      res.status(400);
      throw new Error("Could not create bus");
    }
  } catch (err) {
    if (fileData.filePath) {
      await cloudinary.uploader.destroy(uploadedFile.public_id);
    }
    res.status(500);
    throw new Error(err);
  }
});

//get all buses
const getAllBuses = asyncHandler(async (req, res) => {
  const buses = await Bus.find({});

  if (buses) {
    res.json(buses);
  } else {
    res.status(404);
    throw new Error("No buses found");
  }
});

const getBusById = asyncHandler(async (req, res) => {
  const bus = await Bus.findById(req.params.id);

  if (bus) {
    res.json(bus);
  } else {
    res.status(404);
    throw new Error("Bus not found");
  }
});

//delete bus
const deleteBusById = asyncHandler(async (req, res) => {
  const bus = await Bus.findById(req.params.id);

  if (bus) {
    await bus.deleteOne();
    res.status(200).json({ message: "Bus removed" });
  } else {
    res.status(404);
    throw new Error("Bus not found");
  }
});

module.exports = {
  createBus,
  getAllBuses,
  getBusById,
  deleteBusById,
};
