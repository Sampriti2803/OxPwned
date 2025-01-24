from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import os

# Disable parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

model_name = "mistralai/Mistral-7B-v0.3"

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Ensure padding token is set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# Load model optimized for Apple Silicon
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,  # Use float16 for performance
    device_map={"": torch.device("mps")},  # Use Apple's Metal backend
)


# Function to generate response
def generate_response(prompt):
    inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
    inputs = {k: v.to("mps") for k, v in inputs.items()}  # Move tensors to Apple Metal
    with torch.no_grad():
        outputs = model.generate(
            **inputs, max_new_tokens=100, do_sample=True, top_p=0.95, temperature=0.8
        )
    return tokenizer.decode(outputs[0], skip_special_tokens=True)


# Test
prompt = "What is Retrieval-Augmented Generation?"
response = generate_response(prompt)
print(response)
