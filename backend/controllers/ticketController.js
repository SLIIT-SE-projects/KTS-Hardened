const asyncHandler = require("express-async-handler");
const Ticket = require("../models/ticketModel");
const axios = require("axios");
const sendEmail = require("../util/sendEmail");
const { cleanText, cleanQrSrc } = require("../util/sanitize");

const addTicket = asyncHandler(async (req, res) => {
  const id = req.person._id;
  const name = req.person.fullName;
  const email = req.person.email;

  const { station, total, seatCount, roadRouteId } = req.body;

  // Sanitize inputs
  const safeStation   = cleanText(station);
  const safeTotal     = cleanText(total);
  const safeSeatCount = cleanText(seatCount);
  const safeRouteId   = cleanText(roadRouteId);
  const safeName      = cleanText(name);

  //get the last ticketId
  const lastTicket = await Ticket.find().sort({ ticketId: -1 }).limit(1);

  let ticketId = "";

  if (lastTicket.length === 0) {
    ticketId = "TK#kts1";
  } else {
    const lastTicketId = lastTicket[0].ticketId;
    const lastTicketIdNumber = parseInt(lastTicketId.split("TK#kts")[1]);
    ticketId = `TK#kts${lastTicketIdNumber + 1}`;
  }

  const config = {
    headers: { Authorization: "Bearer b897e3f0-96e3-11f0-9cc1-5726e30758e2" },
  };

  const bodyParameters = {
    colorDark: "#000",
    qrCategory: "url",
    text: `
      ticketId -: ${ticketId}
      station -: ${safeStation}
      total -: ${safeTotal}
      seatCount -: ${safeSeatCount}
      roadRouteId -: ${safeRouteId}
    `,
  };

  let qrCode = "";
  try {
    const qrRes = await axios.post(
      "https://qrtiger.com/api/qr/static",
      bodyParameters,
      config
    );
    qrCode = qrRes.data.url;
  } catch (err) {
    res.status(500);
    throw new Error(err);
  }

  const ticket = new Ticket({
    ticketId,
    userId: id,
    date: Date.now(),
    station: safeStation,
    total: safeTotal,
    seatCount: safeSeatCount,
    roadRouteId: safeRouteId,
    qrCode,
  });

  try {
    const createdTicket = await ticket.save();

    //
    const message = `
      <h2>Hello ${safeName}</h2>
      <h2>${sanitizeHtml(`Hello ${name}`)}</h2>
      <p>You have purchased a QR code from ICI</p>
      <p>Ticket is only valid for 2 days</p>
      <img src="${cleanQrSrc(qrCode)}" width="300" height="300" alt="QR Code"/>
      <p>Regards, ICI</p>
    
    `;

    const subject = "Ticket Purchase";
    const sent_to = email;
    const sent_from = process.env.EMAIL_USER;

    try {
      await sendEmail(subject, message, sent_to, sent_from);
    } catch (err) {
      res.status(500);
      throw new Error("Email didn't not sent,Please try again");
    }

    ///
    res.status(201).json(createdTicket);
  } catch (error) {
    res.status(400);
    throw new Error(error);
  }
});

const getAllTickets = asyncHandler(async (req, res) => {
  try {
    const tickets = await Ticket.find({});
    res.json(tickets);
  } catch (error) {
    res.status(404);
    throw new Error(error);
  }
});

module.exports = { addTicket, getAllTickets };
