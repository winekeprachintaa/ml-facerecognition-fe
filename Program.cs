using Microsoft.AspNetCore.StaticFiles;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();

var provider = new FileExtensionContentTypeProvider();
provider.Mappings[".onnx"] = "application/onnx"; // bisa juga "application/onnx"

app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = provider
});

app.MapFallbackToFile("index.html");

app.Run();
