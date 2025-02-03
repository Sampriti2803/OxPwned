import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer

# ✅ Disable Tokenizer Parallelism to Fix Forking Issue
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# ✅ Enable MPS Optimizations
torch.backends.mps.graphs = True

# Load Tokenizer & Model
model_path = "./deepseek-r1-distill-qwen-7B"
tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)

model = AutoModelForCausalLM.from_pretrained(
    model_path, trust_remote_code=True, torch_dtype=torch.bfloat16, device_map="mps"
).eval()

# ✅ Enable Cache for Faster Generation
model.config.use_cache = True

# ✅ Compile Model for Speedup (Optional)
model = torch.compile(model)  # Only available in PyTorch 2.0+

# Input Prompt
prompt = "Explain difference between teokenisation and conceptualisation."
inputs = tokenizer(prompt, return_tensors="pt").to("mps")

# ✅ Streaming for Real-Time Word-by-Word Generation
streamer = TextStreamer(tokenizer, skip_prompt=True)

print("\n🚀 Generating Output (Faster Word by Word)...\n")
with torch.no_grad():
    model.generate(
        **inputs,
        max_new_tokens=200,  # More tokens allowed
        temperature=0.5,  # Balanced randomness
        top_k=30,  # Keeps search space optimal
        do_sample=True,
        min_length=30,  # Ensures meaningful responses
        typical_p=0.2,  # Makes generation more predictable
        streamer=streamer,  # Stream output word-by-word
        pad_token_id=tokenizer.eos_token_id,
    )

# Extract Final Response
full_response = tokenizer.decode(inputs.input_ids[0], skip_special_tokens=True)
print(f"\n✅ Final Response:\n{full_response}")
