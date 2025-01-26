from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import os

# Set the local path where your model is stored
cache_dir = "/Users/kshitij/.cache/huggingface/hub/"

# Load tokenizer and model from local cache
tokenizer = AutoTokenizer.from_pretrained(
    "mistralai/Mistral-7B-Instruct-v0.3", cache_dir=cache_dir
)

model = AutoModelForCausalLM.from_pretrained(
    "mistralai/Mistral-7B-Instruct-v0.2",
    cache_dir=cache_dir,
    torch_dtype=torch.float16,  # Use float16 for efficiency
    device_map="auto",  # Automatically select GPU/CPU
)


# Function to generate response with instruction tuning
def generate_response(prompt):
    instruction = f"[INST] {prompt} [/INST]"  # Instruct-style prompting
    inputs = tokenizer(instruction, return_tensors="pt", padding=True, truncation=True)
    inputs = {k: v.to("mps") for k, v in inputs.items()}  # Move tensors to Apple Metal
    with torch.no_grad():
        outputs = model.generate(
            **inputs, max_new_tokens=1000, do_sample=True, top_p=0.95, temperature=0.8
        )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)


# Test
prompt = "What are zero-day vulnerabilities and how do I counter them?"
response = generate_response(prompt)
print(response)
