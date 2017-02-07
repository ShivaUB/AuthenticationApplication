using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Models.AuthenticationModels
{
    public class VerifyPhoneNumber
    {
        [Required]
        [Display(Name = "Phone Number")]
        [Phone]
        public string Ph_No { get; set; }

        [Required]
        [StringLength(5, MinimumLength = 5)]
        [Display(Name = "Confirm Code")]
        public string ConfirmCode{ get; set; }
    }
}