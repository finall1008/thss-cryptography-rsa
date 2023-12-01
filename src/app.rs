use std::sync::Arc;

use crate::bigint::BigInt;
use crate::{rsa, utils};
use iced::widget::text_editor::{Action, TextEditor};
use iced::widget::{text_editor, Button, Column, Row, Text, TextInput};
use iced::{Element, Sandbox};

fn content_clear(content: &mut text_editor::Content) {
    content.edit(Action::Move(text_editor::Motion::DocumentStart));
    content.edit(Action::Select(text_editor::Motion::DocumentEnd));
    content.edit(Action::Edit(text_editor::Edit::Delete));
}

fn content_replace_text(content: &mut text_editor::Content, string: String) {
    content_clear(content);
    content.edit(Action::Edit(text_editor::Edit::Paste(Arc::new(string))));
}

pub struct App {
    pub_key: String,
    priv_key: String,
    key_length: String,
    input: text_editor::Content,
    output: text_editor::Content,
    error: String,
    used_time: String,
    n: BigInt,
    d: BigInt,
    n_barrett_m: BigInt,
    key_len: usize,
}

#[derive(Debug, Clone)]
pub enum Message {
    PubKeyChanged(String),
    PrivKeyChanged(String),
    InputChanged(text_editor::Action),
    OutputChanged(text_editor::Action),
    KeyLenChanged(String),
    SwapPressed,
    GenKeyPressed,
    SetKeyPressed,
    EncryptPressed,
    DecryptPressed,
    SignPressed,
    VerifySignPressed,
    ResetPressed,
}

impl App {
    fn get_strip_input(&self) -> String {
        let txt = self.input.text();
        txt.strip_suffix("\n").unwrap_or(&txt).to_owned()
    }
    fn set_used_time(&mut self, t: u128) {
        self.used_time = format!("Used time: {}us", t);
    }
    fn set_input(&mut self, s: String) {
        content_replace_text(&mut self.input, s);
    }
    fn set_output(&mut self, s: String) {
        content_replace_text(&mut self.output, s);
    }
    fn preform_action<F>(&mut self, func: F)
    where
        F: Fn(String) -> String,
    {
        let txt = self.get_strip_input();
        let (t, res) = utils::count_time(|| func(txt.clone()));
        self.set_used_time(t);
        self.set_output(res);
    }
}

impl Sandbox for App {
    type Message = Message;

    fn new() -> Self {
        App {
            pub_key: String::new(),
            priv_key: String::new(),
            key_length: String::from("768"),
            input: text_editor::Content::new(),
            output: text_editor::Content::new(),
            error: String::new(),
            used_time: String::new(),
            n: BigInt::with_capacity(1),
            d: BigInt::with_capacity(1),
            n_barrett_m: BigInt::with_capacity(1),
            key_len: 768,
        }
    }

    fn title(&self) -> String {
        String::from("RSA")
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::PubKeyChanged(s) => {
                self.pub_key = s;
            }
            Message::PrivKeyChanged(s) => {
                self.priv_key = s;
            }
            Message::InputChanged(s) => {
                self.input.edit(s);
            }
            Message::OutputChanged(s) => match s {
                Action::Edit(_) => {}
                _ => self.output.edit(s),
            },
            Message::KeyLenChanged(s) => match s.parse::<usize>() {
                Ok(l) => {
                    self.key_len = l;
                    self.key_length = s;
                }
                Err(_) => {}
            },
            Message::SwapPressed => {
                let mut output_text = self.output.text();
                output_text = output_text
                    .strip_suffix("\n")
                    .unwrap_or(&output_text)
                    .to_owned();
                self.set_input(output_text);
                content_clear(&mut self.output);
            }
            Message::GenKeyPressed => {
                self.error.clear();
                let t;
                (t, (self.n, self.d)) = utils::count_time(|| rsa::gen_keys(self.key_len));
                self.set_used_time(t);
                self.n_barrett_m = self.n.barrett_m();
                (self.pub_key, self.priv_key) = rsa::fmt_key(&self.n, &self.d);
            }
            Message::SetKeyPressed => match rsa::key_from_str(&self.pub_key, &self.priv_key) {
                Ok(r) => {
                    self.error.clear();
                    (self.n, self.d, self.key_len) = r;
                    self.n_barrett_m = self.n.barrett_m();
                    self.key_length = format!("{}", self.key_len);
                }
                Err(e) => self.error = e.to_owned(),
            },
            Message::EncryptPressed => {
                if self.error != "" {
                    self.error = String::from("You need to regenerate/reset keys");
                } else {
                    let n = self.n.clone();
                    let m = self.n_barrett_m.clone();
                    self.preform_action(|s| rsa::encrypt(&s, &n, &m));
                }
            }
            Message::DecryptPressed => {
                if self.error != "" {
                    self.error = String::from("You need to regenerate/reset keys");
                } else {
                    let n = self.n.clone();
                    let m = self.n_barrett_m.clone();
                    let d = self.d.clone();
                    self.preform_action(|s| rsa::decrypt(&s, &n, &m, &d));
                }
            }
            Message::SignPressed => {
                if self.error != "" {
                    self.error = String::from("You need to regenerate/reset keys");
                } else {
                    let n = self.n.clone();
                    let m = self.n_barrett_m.clone();
                    let d = self.d.clone();
                    self.preform_action(|s| format!("{}\n{}", s, rsa::sign(&s, &n, &m, &d)));
                }
            }
            Message::VerifySignPressed => {
                if self.error != "" {
                    self.error = String::from("You need to regenerate/reset keys");
                } else {
                    let n = self.n.clone();
                    let m = self.n_barrett_m.clone();
                    self.preform_action(|s| {
                        let sp = s.split("\n").collect::<Vec<_>>();
                        if sp.len() != 2 {
                            return String::from("Invalid input for verify sign");
                        }
                        let msg = sp[0];
                        let sign = sp[1];
                        let (res, ver_msg) = rsa::ver_sign(msg, sign, &n, &m);
                        format!("{}\n{}", res, ver_msg)
                    });
                }
            }
            Message::ResetPressed => {
                *self = App {
                    pub_key: String::new(),
                    priv_key: String::new(),
                    key_length: String::from("768"),
                    input: text_editor::Content::new(),
                    output: text_editor::Content::new(),
                    error: String::new(),
                    used_time: String::new(),
                    n: BigInt::with_capacity(1),
                    d: BigInt::with_capacity(1),
                    n_barrett_m: BigInt::with_capacity(1),
                    key_len: 768,
                }
            }
        }
    }

    fn view(&self) -> Element<Message> {
        Column::new()
            .push(
                Row::new()
                    .push(
                        TextInput::new("公钥", &self.pub_key)
                            .padding(10)
                            .on_input(Message::PubKeyChanged),
                    )
                    .push(
                        TextInput::new("私钥", &self.priv_key)
                            .padding(10)
                            .on_input(Message::PrivKeyChanged)
                            .password(),
                    )
                    .push(
                        TextInput::new("密钥长度", &self.key_length)
                            .padding(10)
                            .on_input(Message::KeyLenChanged),
                    ),
            )
            .push(
                Row::new()
                    .push(
                        Button::new("Generate Key")
                            .on_press(Message::GenKeyPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Set Key")
                            .on_press(Message::SetKeyPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Encrypt")
                            .on_press(Message::EncryptPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Decrypt")
                            .on_press(Message::DecryptPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Sign")
                            .on_press(Message::SignPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Verify Sign")
                            .on_press(Message::VerifySignPressed)
                            .padding(10),
                    )
                    .push(
                        Button::new("Reset")
                            .on_press(Message::ResetPressed)
                            .padding(10),
                    )
                    .push(Text::new(&self.used_time)),
            )
            .push(Text::new(&self.error))
            .push(
                Row::new()
                    .push(
                        TextEditor::new(&self.input)
                            .padding(10)
                            .on_edit(Message::InputChanged),
                    )
                    .push(Button::new("<-").on_press(Message::SwapPressed).padding(10))
                    .push(
                        TextEditor::new(&self.output)
                            .padding(10)
                            .on_edit(Message::OutputChanged),
                    ),
            )
            .into()
    }
}
