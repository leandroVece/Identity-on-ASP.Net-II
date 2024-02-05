namespace User.Management.Models;

public class ApiResponse<T>
{
    public bool IsSucees {get;set;}
    public string Message {get;set;}
    public int Status {get;set;}
    public T? Respose {get;set;}
    
}