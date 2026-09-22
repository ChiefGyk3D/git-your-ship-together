// The fixture's one sketch: enough for arduino-cli to compile for a board,
// and small enough that the AVR core is the only thing the job downloads.
const unsigned long PERIOD_MS = 500;

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
  digitalWrite(LED_BUILTIN, HIGH);
  delay(PERIOD_MS);
  digitalWrite(LED_BUILTIN, LOW);
  delay(PERIOD_MS);
}
