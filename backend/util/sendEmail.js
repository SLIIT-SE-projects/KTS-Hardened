const nodemailer = require("nodemailer");

/**
 * Send an email with optional HTML and required plain-text fallback.
 * @param {string} subject
 * @param {string|null} html - pass null to send text-only
 * @param {string} to
 * @param {string} from
 * @param {string} text - plain-text body (already sanitized)
 * @param {string|undefined} replyTo
 */
module.exports = async function sendEmail(subject, html, to, from, text, replyTo) {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: Number(process.env.EMAIL_PORT || 587),
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: { rejectUnauthorized: false },
  });

  const mail = {
    from,
    to,
    subject: String(subject),
    // Include HTML only if provided; always include safe text
    ...(html ? { html } : {}),
    text: String(text ?? ""),
    ...(replyTo ? { replyTo } : {}),
  };

  await transporter.sendMail(mail);
};
