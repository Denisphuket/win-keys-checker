// KeyDetail.cs
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace KeyCheckerApi.Models
{
    public class KeyDetail
    {
        public string ProductKey { get; set; }
        public string? KeyPid { get; set; } // Допускается null
        public string? Eid { get; set; } // Допускается null
        public string? Aid { get; set; } // Допускается null
        public string? Edi { get; set; } // Допускается null
        public string? Sub { get; set; } // Допускается null
        public string? Lit { get; set; } // Допускается null
        public string? Lic { get; set; } // Допускается null
        public string? Cid { get; set; } // Допускается null
        public string? Prd { get; set; } // Допускается null

        public KeyDetail(string productKey)
        {
            ProductKey = productKey;
            // При создании экземпляра класса все остальные свойства могут быть не инициализированы (null)
        }
    }
}
