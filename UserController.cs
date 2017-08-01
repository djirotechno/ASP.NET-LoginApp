using LoginApp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace LoginApp.Controllers
{
    public class UserController : Controller
    {
        //Registration Action 

        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        //Registration Post Action 

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration ([Bind(Exclude ="IsEmailverified,ActivationCode")]User user)
        {

            bool Status = false;
            string message = "";


            //model validation
            if (ModelState.IsValid)
            {

                #region email is already exist 
                var isExist = IsEmailExist(user.EmailID);
                if (isExist)
                {
                    ModelState.AddModelError("EmailExist", "Email already exist");
                    return View(user);
                }
                #endregion
                #region  generate activation code
                user.ActivationCode = Guid.NewGuid();
                #endregion

                #region Password hashing
                user.Password = Crypto.Hash(user.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword);

                #endregion
                user.IsEmailverified = false;


                #region  Save data to Database
                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    dc.User.Add(user);
                    dc.SaveChanges();
                    //send Email User
                    SenVerificationLinkEmail(user.EmailID, user.ActivationCode.ToString());
                    message = "Registration succefully done.Account active link" + "sent to you id:" + user.EmailID;

                    Status = true;

                }
                #endregion
                
            }
            else
            {
                message = " invalide request";
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;
            return View(user);



        }
        //verifyAccount
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false;//this line i have to avoid 
                                                               //confirm password does not match issue on save change
                var v = dc.User.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if(v!= null)
                {
                    v.IsEmailverified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        //Verify Email Link



        //Login
        [HttpGet]
        public ActionResult Login()
        {

            return View();
        }

        //Login Post
        [HttpPost]
        public ActionResult Login(UserLogin login, string ReturnUrl="")
        {
            string message = "";
            using(MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.User.Where(a => a.EmailID == login.EmailID).FirstOrDefault();
                if (v != null)
                {
                    if (string.Compare(Crypto.Hash(login.Password), v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 525600 : 20;// 525600 = 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);
                        if (Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                    else
                    {
                        message = "Invalid credential provided";
                    }


                }
                else
                {
                    message = "Invalid credential provided";
                }
            }
            ViewBag.Message = message;
            return View();
        }


        //Logout
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }

        [NonAction]
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.User.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }
        [NonAction]
        public void SenVerificationLinkEmail(string emailID,string ActivationCode)
        {
            //var scheme = Request.Url.Scheme;
            //var host = Request.Url.Host;
            //var port = Request.Url.Port;

            //string url = scheme + "://" + host

            var verifyUrl = "/User/VerifyAccount/" + ActivationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);
            var fromEmail = new MailAddress("djirotech@gmail.com", "djirotech");
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "1234";
            string subject = "your account is successfully created!";
            string body = "<br></br>we ar exist to tell" + "<br></br><a href='" + link + "'>" + link + "</a>";
            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)

            };

            using (var message = new MailMessage(fromEmail, toEmail)

            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })

                smtp.Send(message);


        }
    }

   

}