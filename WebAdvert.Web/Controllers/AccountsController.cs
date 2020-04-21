using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        public AccountsController(
            SignInManager<CognitoUser> signInManager,
            UserManager<CognitoUser> userManager,
            CognitoUserPool pool
             )
        {
            _signInManager = signInManager;
            _userManager = userManager as CognitoUserManager<CognitoUser>;
            _pool = pool;
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);

                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExist", "User with this email already exist");

                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);

                var createResult = await _userManager.CreateAsync(user, model.Password);

                if (createResult.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    ModelState.AddModelError("UserNotFound", "User with given email is not found");
                    return View(model);
                }

                var result = await _userManager.ConfirmSignUpAsync(user, model.Code, false);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match");
                    return View(model);
                }
            }

            return View("Login", model);
        }

        [HttpGet]
        public async Task<IActionResult> ForgotPasswordForm()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPasswordForm(ForgotPasswordFormModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    await user.ForgotPasswordAsync();

                    return RedirectToAction("RecoverPasswordForm", new { email = model.Email });
                }
                else
                {
                    ModelState.AddModelError("ForgotPasswordFormError", "User was not found");
                    return View(model);
                }
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> RecoverPasswordForm(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Index", "Home");
            }

            return View(new RecoverPasswordForm() { Email = email });
        }

        [HttpPost]
        [ActionName("RecoverPasswordForm")]
        public async Task<IActionResult> RecoverPasswordFormPost(RecoverPasswordForm model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Login");
                    }
                    else
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError(error.Code, error.Description);
                        }
                        return View(model);
                    }
                }
                else
                {
                    ModelState.AddModelError("RecoverPasswordFormPost", "User was not found");
                    return View(model);
                }
            }

            return View(model);
        }

        [Authorize]
        public Task<IActionResult> EnableMFA()
        {
            var user = await _userManager.FindByEmailAsync("");
        }
    }
}