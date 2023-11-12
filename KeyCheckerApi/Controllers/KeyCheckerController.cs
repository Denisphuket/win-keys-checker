using Microsoft.AspNetCore.Mvc;
using KeyCheckerApi.Services;
using KeyCheckerApi.Models;

namespace KeyCheckerApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class KeyCheckerController : ControllerBase
    {
        // Пример метода, который вызывает статический метод PIDChecker и использует POST
        [HttpPost("check")] // Добавлен маршрут "check" для метода POST
        public async Task<ActionResult<KeyDetail>> CheckKey([FromBody] KeyRequest request)
        {
            // Проверка на null перед использованием ProductKey
            if (string.IsNullOrWhiteSpace(request.ProductKey))
            {
                return BadRequest("ProductKey must be provided and not empty.");
            }

            try
            {
                // Теперь мы уверены, что request.ProductKey не null
                var result = PIDChecker.Check(request.ProductKey);
                if (result != null)
                {
                    // Теперь получаем оставшиеся активации для данного продукта
                    result.RemainingActivations = await PIDChecker.GetRemainingActivationsAsync(result.KeyPid);
                    return Ok(result);
                }
                else
                {
                    return NotFound("Key not found or invalid.");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Internal server error: " + ex.Message);
            }
        }
    }

    // Вспомогательный класс для представления тела запроса
    public class KeyRequest
    {
        public string? ProductKey { get; set; }
    }
}
