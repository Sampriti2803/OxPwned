import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer

torch.backends.mps.graphs = True  # Enable MPS Graphs for Apple Silicon

# Load Tokenizer & Model
model_path = "./deepseek-r1-distill-qwen-7B"
tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)

model = AutoModelForCausalLM.from_pretrained(
    model_path, trust_remote_code=True, torch_dtype=torch.bfloat16, device_map="mps"
).eval()  # REMOVED `attn_implementation="flash_attention_2"`

# Enable caching for faster inference
model.config.use_cache = True

# Prepare Input
prompt = "Explain how neural networks learn in three sentences."
inputs = tokenizer(prompt, return_tensors="pt").to("mps")

# Real-Time Streaming
streamer = TextStreamer(tokenizer, skip_prompt=True)

print("\n🚀 Generating Output Faster...\n")
with torch.no_grad():
    model.generate(
        **inputs,
        max_new_tokens=50,  # Limit to 50 tokens (reduces time)
        temperature=0.5,  # Slightly lower for faster predictions
        top_p=0.9,
        top_k=50,  # Consider only top 50 words
        do_sample=True,
        typical_p=0.2,  # More predictable words
        streamer=streamer,  # Enables real-time streaming
        pad_token_id=tokenizer.eos_token_id,
    )

# Extract Final Response
full_response = tokenizer.decode(inputs.input_ids[0], skip_special_tokens=True)
print(f"\n✅ Final Response:\n{full_response}")
