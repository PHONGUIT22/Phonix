"""Phonix v2.0 Micro-Router QLoRA Fine-Tuning Pipeline.

Fine-tunes Qwen2.5-Coder-1.5B-Instruct into a dedicated AST Triage & Complexity
Scoring Micro-Router using Unsloth / Hugging Face PEFT within the 1.2 GB VRAM cap.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phonix.train_router")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune Phonix Micro-Router via LoRA / QLoRA")
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/phonix_router_sft_dataset.jsonl",
        help="Path to mined SFT dataset in ChatML format",
    )
    parser.add_argument(
        "--model-id",
        type=str,
        default="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        help="HuggingFace model ID or local path",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/phonix-router-lora",
        help="Directory to save LoRA adapter weights",
    )
    parser.add_argument(
        "--max-seq-length",
        type=int,
        default=4096,
        help="Context window max sequence length (4096)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2,
        help="Per-device train batch size",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-4,
        help="Learning rate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate dataset and print training plan without loading GPU weights",
    )
    return parser.parse_args()


def validate_dataset(dataset_path: str) -> list[dict]:
    """Validates that dataset conforms to ChatML format with required schema fields."""
    p = Path(dataset_path)
    if not p.is_file():
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    valid_samples = []
    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {idx}: {exc}") from exc

            if "messages" not in data or len(data["messages"]) != 3:
                raise ValueError(f"Line {idx} missing 3-message ChatML structure.")

            assistant_msg = data["messages"][2]["content"]
            try:
                parsed_res = json.loads(assistant_msg)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {idx} assistant message is not valid JSON: {exc}") from exc

            if "selected_ast_frames" not in parsed_res or "routing_decision" not in parsed_res:
                raise ValueError(f"Line {idx} missing required router decision fields.")

            valid_samples.append(data)

    logger.info("Dataset validated: %d valid ChatML samples found in %s", len(valid_samples), dataset_path)
    return valid_samples


def main() -> None:
    args = parse_args()

    print("=" * 70)
    print(" Phonix v2.0 - Micro-Router 1.5B QLoRA Fine-Tuning Pipeline")
    print("=" * 70)
    print(f" [*] Base Model:        {args.model_id}")
    print(f" [*] SFT Dataset:       {args.dataset}")
    print(f" [*] Output Directory:  {args.output_dir}")
    print(f" [*] Max Seq Length:    {args.max_seq_length}")
    print(f" [*] LoRA Rank:         r=16, alpha=32, target=['q_proj', 'k_proj', 'v_proj', 'o_proj']")
    print(f" [*] Target VRAM Cap:   1.2 GB (Q4_K_M 4-bit Quantization)")
    print("-" * 70)

    samples = validate_dataset(args.dataset)

    if args.dry_run:
        print("[+] Dry-run validation successful! Dataset is 100% compliant with Router SFT schema.")
        print("    To run fine-tuning with GPU acceleration:")
        print(f"    python scripts/train_router_lora.py --dataset {args.dataset} --output-dir {args.output_dir}")
        print("=" * 70)
        return

    # Attempt importing Unsloth or PEFT/Transformers
    try:
        from unsloth import FastLanguageModel  # type: ignore
        use_unsloth = True
        logger.info("Unsloth fast kernels detected.")
    except ImportError:
        use_unsloth = False
        logger.info("Unsloth not detected. Falling back to HuggingFace TRL / PEFT.")

    try:
        from datasets import Dataset  # type: ignore
        from transformers import TrainingArguments  # type: ignore
        from trl import SFTTrainer  # type: ignore
    except ImportError:
        logger.warning(
            "PyTorch/Transformers training packages not installed in current environment.\n"
            "Install training dependencies via:\n"
            "  pip install torch transformers datasets peft trl unsloth\n"
            "Or train on Google Colab / GPU instance using data/phonix_router_sft_dataset.jsonl."
        )
        print("\n[!] Verified dataset format. Exiting gracefully without GPU dependencies.")
        return

    # Format into training prompt format
    formatted_dataset = []
    for item in samples:
        text = ""
        for msg in item["messages"]:
            text += f"<|im_start|>{msg['role']}\n{msg['content']}<|im_end|>\n"
        formatted_dataset.append({"text": text})

    train_ds = Dataset.from_list(formatted_dataset)

    if use_unsloth:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=args.model_id,
            max_seq_length=args.max_seq_length,
            load_in_4bit=True,
        )
        model = FastLanguageModel.get_peft_model(
            model,
            r=16,
            lora_alpha=32,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
            lora_dropout=0.05,
            bias="none",
        )
    else:
        from peft import LoraConfig, get_peft_model  # type: ignore
        from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore

        tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            args.model_id,
            load_in_4bit=True,
            device_map="auto",
            trust_remote_code=True,
        )
        peft_config = LoraConfig(
            r=16,
            lora_alpha=32,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, peft_config)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        max_steps=len(samples) * args.epochs,
        learning_rate=args.learning_rate,
        fp16=True,
        logging_steps=1,
        optim="adamw_8bit",
        save_strategy="epoch",
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=train_ds,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        tokenizer=tokenizer,
        args=training_args,
    )

    logger.info("Starting fine-tuning...")
    trainer.train()

    logger.info("Saving LoRA adapter to %s...", args.output_dir)
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"\n[+] Fine-tuning complete. Adapter saved to {args.output_dir}")


if __name__ == "__main__":
    main()
