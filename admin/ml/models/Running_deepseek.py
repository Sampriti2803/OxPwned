import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer

# ⚡ Enable MPS Graphs for Faster Computation
torch.backends.mps.graphs = True

# Load Tokenizer & Model
model_path = "./deepseek-r1-distill-qwen-7B"
tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)

model = AutoModelForCausalLM.from_pretrained(
    model_path, trust_remote_code=True, torch_dtype=torch.bfloat16, device_map="mps"
).eval()

# Enable Cache for Speedup
model.config.use_cache = True

# Input Prompt
prompt = "Explain how neural networks learn in three sentences."
inputs = tokenizer(prompt, return_tensors="pt").to("mps")

# ⚡ Streaming for Real-Time Word-by-Word Generation
streamer = TextStreamer(tokenizer, skip_prompt=True)

print("\n🚀 Generating Output (Word by Word)...\n")
with torch.no_grad():
    model.generate(
        **inputs,
        max_new_tokens=50,  # Keep it short for speed
        temperature=0.4,  # Lower temperature for quicker word selection
        top_k=20,  # Reduce to consider only top 20 words (faster)
        do_sample=True,
        typical_p=0.2,  # Makes generation more predictable
        streamer=streamer,  # Stream output word-by-word
        pad_token_id=tokenizer.eos_token_id,
    )

# Extract Final Response
full_response = tokenizer.decode(inputs.input_ids[0], skip_special_tokens=True)
print(f"\n✅ Final Response:\n{full_response}")
