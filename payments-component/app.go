package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/checkout/session"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	stripe.Key = os.Getenv("STRIPE_KEY")
}

func createCheckoutSession(w http.ResponseWriter, r *http.Request) {
  err := godotenv.Load(".env")
  if err != nil {
    log.Fatal("Error loading .env file")
  }
  port := os.Getenv("PORT")
  if port == "" {
    port = "8080"
  }
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
					Currency: stripe.String("usd"),
					ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
						Name: stripe.String("Test Product"),
					},
					UnitAmount: stripe.Int64(2000), // $20.00
				},
				Quantity: stripe.Int64(1),
			},
		},
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String("http://localhost:"+port+"/success"),
		CancelURL:  stripe.String("http://localhost:"+port+"/cancel"),
	}

	session, err := session.New(params)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating checkout session: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect to the Stripe Checkout session
	http.Redirect(w, r, session.URL, http.StatusSeeOther)
}

func renderTemplate(w http.ResponseWriter, tmpl string) {
	t, err := template.ParseFiles("pages/" + tmpl + ".html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, nil)
}

func startServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "index")
	})

	http.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "success")
	})

	http.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "cancel")
	})

	// Stripe payment route
	http.HandleFunc("/create-checkout-session", createCheckoutSession)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Server started on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func main() {
	// Start the server
	startServer()
}
