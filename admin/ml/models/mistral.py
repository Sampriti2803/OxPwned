from transformers import AutoTokenizer, AutoModelForCausalLM

# Authenticate with your Hugging Face token
huggingface_token = (
    "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"  # Replace with your actual token
)
model_name = "mistralai/Mistral-7B-v0.3"

# Load tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_name, use_auth_token=huggingface_token)
model = AutoModelForCausalLM.from_pretrained(
    model_name, use_auth_token=huggingface_token, device_map="auto"
)


# Example usage
def generate_response(prompt):
    inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
    outputs = model.generate(
        **inputs, max_length=200, do_sample=True, top_p=0.95, temperature=0.8
    )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)


# Test the model
prompt = "What is Retrieval-Augmented Generation?"
response = generate_response(prompt)
print(response)
